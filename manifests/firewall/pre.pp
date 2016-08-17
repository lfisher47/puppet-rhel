# Class: rhel::firewall::pre
#
class rhel::firewall::pre (
  $ipv6,
  $icmp_limit,
) {

  # Break dependency cycle
  Firewall { require => undef }

  rhel::firewall::dualstack { '001 state related established accept RULE':
    ipv6  => $ipv6,
    rules => {
      action => 'accept',
      chain  => 'INPUT',
      proto  => 'all',
      state  => [ 'RELATED', 'ESTABLISHED' ],
    },
  }
  rhel::firewall::dualstack { "001 state related accept LOG":
    ipv6  => $ipv6,
    rules => {
      ensure     => 'present',
      jump       => 'LOG',
      chain      => 'INPUT',
      proto      => 'all',
      state      => [ 'RELATED' ],
      log_prefix => 'INPUT RELATED: ',
      log_level  => '7',
    },
  }

  # Different protocols, icmp vs. ipv6-icmp
  if $icmp_limit != false {
    validate_re($icmp_limit, '^\d+$', '$icmp_limit must be an integer')
    firewall { '002 icmp drop timestamp-request RULE':
      action => 'drop',
      chain  => 'INPUT',
      icmp   => 'timestamp-request',
      proto  => 'icmp',
    }
    firewall { '002 icmp drop timestamp-request LOG':
      ensure     => $ensure,
      jump       => 'LOG',
      chain      => 'INPUT',
      icmp       => 'timestamp-request',
      proto      => 'icmp',
      log_prefix => 'INPUT DROP icmp timestamp-request',
      log_level  => '7'
    }
    firewall { '003 icmp limit rate RULE':
      action => 'accept',
      chain  => 'INPUT',
      limit  => "${icmp_limit}/sec",
      proto  => 'icmp',
    }
    firewall { '003 icmp limit rate LOG':
      ensure     => $ensure,
      jump       => 'LOG',
      chain      => 'INPUT',
      limit      => "${icmp_limit}/sec",
      proto      => 'icmp',
      log_prefix => 'INPUT icmp limit rate',
      log_level  => '7'
    }
    firewall { '004 icmp drop RULE':
      action => 'drop',
      chain  => 'INPUT',
      proto  => 'icmp',
    }
    firewall { '004 icmp drop LOG':
      ensure     => $ensure,
      jump       => 'LOG',
      chain      => 'INPUT',
      proto      => 'icmp',
      log_prefix => 'INPUT DROP icmp',
      log_level  => '7'
    }
    if $ipv6 {
      firewall { '003 ipv6-icmp limit rate':
        action   => 'accept',
        chain    => 'INPUT',
        limit    => "${icmp_limit}/sec",
        proto    => 'ipv6-icmp',
        provider => 'ip6tables',
      }
      firewall { '004 ipv6-icmp drop':
        action   => 'drop',
        chain    => 'INPUT',
        proto    => 'ipv6-icmp',
        provider => 'ip6tables',
      }
    }
  } else {
    firewall { '003 icmp accept RULE':
      action => 'accept',
      chain  => 'INPUT',
      proto  => 'icmp',
    }
    firewall { '003 icmp accept LOG':
      ensure     => $ensure,
      jump       => 'LOG',
      chain      => 'INPUT',
      proto      => 'icmp',
      log_prefix => 'INPUT ACCEPT icmp',
      log_level  => '7'
    }
    if $ipv6 {
      firewall { '003 ipv6-icmp accept':
        action   => 'accept',
        chain    => 'INPUT',
        proto    => 'ipv6-icmp',
        provider => 'ip6tables',
      }
    }
  }

  rhel::firewall::dualstack { '005 lo accept RULE':
    ipv6  => $ipv6,
    rules => {
      action  => 'accept',
      chain   => 'INPUT',
      iniface => 'lo',
      proto   => 'all',
    },
  }
  rhel::firewall::dualstack { "005 lo accept LOG":
    ipv6  => $ipv6,
    rules => {
      ensure     => 'present',
      jump       => 'LOG',
      chain      => 'INPUT',
      proto      => 'all',
      iniface    => 'lo',
      log_prefix => 'INPUT ACCEPT LO: ',
      log_level  => '7',
    },
  }

}

