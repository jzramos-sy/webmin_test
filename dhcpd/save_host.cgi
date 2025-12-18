#!/usr/local/bin/perl
# save_host.cgi
# Update, create or delete a host

require './dhcpd-lib.pl';
require './params-lib.pl';
&ReadParse();

# --- CUSTOM CODE START: Logic for Tempo & Activate Buttons ---
# This runs BEFORE validation to modify the data based on your buttons

if ($in{'tempo_disconnect'}) {
    # 1. Get Today's Date
    my ($sec,$min,$hour,$mday,$mon,$year) = localtime(time());
    $year += 1900; 
    $mon += 1;
    my $datetoday = sprintf("%04d-%02d-%02d", $year, $mon, $mday);

    # 2. Append Date to Name (e.g., "Modem1" -> "Modem1-Tempo-2025-12-18")
    if ($in{'name'} !~ /Tempo/) {
        $in{'name'} = $in{'name'} . "-Tempo-" . $datetoday;
    }

    # 3. Backup MAC to Description and Clear the Hardware Field
    # This effectively "disconnects" them from DHCP
    if ($in{'hardware'}) {
        $in{'desc'} = "MAC_BACKUP:" . $in{'hardware'} . " " . $in{'desc'};
    }
    $in{'hardware'} = ""; # Clear the MAC
    $in{'delete'} = 0;    # Ensure we save, not delete
}
elsif ($in{'activate_host'}) {
    # 1. Find the hidden MAC in the description
    if ($in{'desc'} =~ /MAC_BACKUP:([0-9a-fA-F:]+)/) {
        $in{'hardware'} = $1; # Restore MAC
        $in{'desc'} =~ s/MAC_BACKUP:$1\s*//; # Clean up description
    }

    # 2. Fix the Name (Remove "-Tempo-Date")
    $in{'name'} =~ s/-Tempo-\d{4}-\d{2}-\d{2}//;
    $in{'delete'} = 0;
}
# --- CUSTOM CODE END ---

&lock_all_files();
($par, $host, $indent, $npar, $nindent) = get_branch('hst', $in{'new'});

# check acls
%access = &get_module_acl();
&error_setup($text{'eacl_aviol'});
if ($in{'delete'}) {
	&error("$text{'eacl_np'} $text{'eacl_pdh'}")
		if !&can('rw', \%access, $host, 1);
	}
elsif ($in{'options'}) {
	&error("$text{'eacl_np'} $text{'eacl_psh'}")
		if !&can('r', \%access, $host);
	}
elsif ($in{'new'}) {
	&error("$text{'eacl_np'} $text{'eacl_pih'}")
		unless &can('c', \%access, $host) && 
				&can('rw', \%access, $par) &&
				(!$npar || &can('rw', \%access, $npar));
	}
else {
	&error("$text{'eacl_np'} $text{'eacl_puh'}")
		unless &can('rw', \%access, $host) &&
			(!$npar || &can('rw', \%access, $npar));
	$oldname = $host->{'values'}->[0];
	}

# save
if ($in{'delete'}) {
	# Delete this host
	&error_setup($text{'shost_faildel'});
	&save_directive($par, [ $host ], [ ], 0);
	&drop_dhcpd_acl('hst', \%access, $host->{'values'}->[0]);
	}
elsif ($in{'options'}) {
	# Redirect to client options
	&redirect("edit_options.cgi?sidx=$in{'sidx'}&uidx=$in{'uidx'}&gidx=$in{'gidx'}&idx=$in{'idx'}");
	exit;
	}
else {
	&error_setup($text{'shost_failsave'});

	# Validate and save inputs
	$in{'name'} =~ /^[a-z0-9\.\-\_]+$/i ||
		&error("'$in{'name'}' $text{'shost_invalidhn'}");
	$host->{'comment'} = $in{'desc'};

	# Check for a hostname clash
	if (($in{'new'} || $in{'name'} ne $host->{'values'}->[0]) &&
	    $access{'uniq_hst'}) {
		foreach $h (&get_my_shared_network_hosts($npar)) {
                        &error("$text{'eacl_np'} $text{'eacl_uniq'}")
                                if (lc($h->{'values'}->[0]) eq lc($in{'name'}));
                        }
		}
	$host->{'values'} = [ $in{'name'} ];

	if ($in{'hardware'}) {
		# Check for hardware clash
		$oldhard = $in{'new'} ? undef
				      : &find("hardware", $host->{'members'});
		if ((!$oldhard || $in{'hardware'} ne $oldhard->{'values'}->[1])
		    && $access{'uniq_hst'}) {
			foreach $h (&get_my_shared_network_hosts($npar)) {
				$chard = &find("hardware", $h->{'members'});
				&error("$text{'eacl_np'} $text{'eacl_uniqh'}")
					if ($chard && lc($chard->{'values'}->[1]) eq lc($in{'hardware'}));
				}
			}

		# Convert from Windows / Cisco formats
		$in{'hardware'} =~ s/-/:/g;
		if ($in{'hardware'} =~ /^([0-9a-f]{2})([0-9a-f]{2}).([0-9a-f]{2})([0-9a-f]{2}).([0-9a-f]{2})([0-9a-f]{2}).([0-9a-f]{2})([0-9a-f]{2})$/i) {
			$in{'hardware'} = "$1:$2:$3:$4:$5:$6";
			}
		# Handle an Ethernet address with no formatting at all
		if ($in{'hardware'} =~ /^([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i) {
			$in{'hardware'} = "$1:$2:$3:$4:$5:$6";
			}
		$in{'hardware'} =~ /^([0-9a-f]{1,2}:)*[0-9a-f]{1,2}$/i ||
			&error(&text('shost_invalidhwa', $in{'hardware'},
				     $in{'hardware_type'}) );
		@hard = ( { 'name' => 'hardware',
			    'values' => [ $in{'hardware_type'},
					  $in{'hardware'} ] } );
		}
	&save_directive($host, 'hardware', \@hard);

	if ($in{'fixed-address'}) {
		# Check for IP clash
		$oldfixed = $in{'new'} ? undef
			      : &find("fixed-address", $host->{'members'});
		if ((!$oldfixed ||
		    $in{'fixed-address'} ne $oldfixed->{'values'}->[0])
		    && $access{'uniq_hst'}) {
			foreach $h (&get_my_shared_network_hosts($npar)) {
				$cfixed = &find("fixed-address",
						$h->{'members'});
				&error("$text{'eacl_np'} $text{'eacl_uniqi'}")
					if ($cfixed && lc($cfixed->{'values'}->[0]) eq lc($in{'fixed-address'}));
				}
			}

		# Save IP address
		if ($in{'fixed-address'} !~ /^[\w\s\.\-,]+$/ ||
		    $in{'fixed-address'} =~ /(^|[\s,])[-_]/ ||
		    $in{'fixed-address'} =~ /\.([\s,\.]|$)/ ||
		    $in{'fixed-address'} =~ /(^|[\s,])\d+\.[\d\.]*[a-z_]/i) {
			&error(&text('shost_invalidaddr', $in{'fixed-address'}));	
			}
		@fixedip = split(/[,\s]+/, $in{'fixed-address'});
		@fixed = ( { 'name' => 'fixed-address',
			     'values' => [ join(" , ", @fixedip) ] } );
		}
	&save_directive($host, 'fixed-address', \@fixed);

	&parse_params($host);

	@partypes = ( "", "shared-network", "subnet", "group" );
	if (!$npar || $in{'assign'} > 0 && $npar->{'name'} ne $partypes[$in{'assign'}]) {
		if ($in{'jsquirk'}) {
			&error($text{'shost_invassign'});
			}
		else {
			&redirect("edit_host.cgi?assign=".$in{'assign'}.
				"&idx=".$in{'idx'}."&gidx=".$in{'gidx'}.
				"&uidx=".$in{'uidx'}."&sidx=".$in{'sidx'});
			exit;
			}
		}
	if ($in{'new'}) {
		# save acl for new host
		&save_dhcpd_acl('rw', 'hst', \%access, $in{'name'});
		# Add to the end of the parent structure
		&save_directive($npar, [ ], [ $host ], $nindent);
		}
	elsif ($par eq $npar) {
		# Update host
		&save_directive($par, [ $host ], [ $host ], $indent);
		if ($oldname ne $in{'name'}) {
			&drop_dhcpd_acl('hst', \%access, $oldname);
			&save_dhcpd_acl('rw', 'hst', \%access, $in{'name'});
			}
		}
	else {
		# Move this host
		&save_directive($par, [ $host ], [ ], 0);
		&save_directive($npar, [ ], [ $host ], $nindent);
		}
	}
&flush_file_lines();
&unlock_all_files();
&webmin_log($in{'delete'} ? 'delete' : $in{'new'} ? 'create' : 'modify',
	    'host', $host->{'values'}->[0], \%in);

# --- CUSTOM CODE START: Trigger External Speed Script ---
# This passes the IP, MAC, and TEMPO (Speed) to your Linux script
# The script will handle the actual 'tc' commands or firewall blocks

my $cmd_ip = $in{'fixed-address'};
my $cmd_mac = $in{'hardware'};
my $cmd_tempo = $in{'tempo'};

if ($in{'delete'}) {
    # If deleting, trigger disconnect
    system("/usr/local/bin/manage_modem.sh disconnect '$cmd_ip' &");
} 
elsif ($cmd_ip) {
   # If MAC is empty (Tempo Disconnect was clicked), ensure disconnect
   if (!$cmd_mac) {
       system("/usr/local/bin/manage_modem.sh disconnect '$cmd_ip' &");
   } else {
       # Otherwise connect/update with new speed
       # Format: manage_modem.sh connect [IP] [MAC] [SPEED]
       system("/usr/local/bin/manage_modem.sh connect '$cmd_ip' '$cmd_mac' '$cmd_tempo' &");
   }
}
# --- CUSTOM CODE END ---

if ($in{'ret'} eq "group") {
	$retparms = "sidx=$in{'sidx'}&uidx=$in{'uidx'}&idx=$in{'gidx'}";
	}
elsif ($in{'ret'} eq "subnet") {
	$retparms = "sidx=$in{'sidx'}&idx=$in{'uidx'}";
	}
elsif ($in{'ret'} eq "shared") {
	$retparms = "idx=$in{'sidx'}";
	}

&redirect($in{'ret'} ? "edit_$in{'ret'}.cgi?$retparms" : "");
