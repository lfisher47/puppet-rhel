# Class: rhel::firewall::post
#
class rhel::firewall::post (
  $ipv6,
  $ipv4_action,
  $ipv4_reject_with,
  $ipv6_action,
  $ipv6_reject_with,
  $ipv4_chain_action,
  $ipv6_chain_action,
  $log_rejects,
) {

  # Break dependency cycle
  Firewall { before => undef }

  if $log_rejects {
    firewall { '996 log rejects':
      jump   => 'LOG',
      chain  => 'INPUT',
      proto  => 'all',
      log_prefix => 'INPUT DROP: ',
      log_level  => '7'
    }
    firewall { '997 log rejects':
      jump   => 'LOG',
      chain  => 'FORWARD',
      proto  => 'all',
      log_prefix => 'FORWARD DROP: ',
      log_level  => '7'
    }
  }
  if $ipv4_action == 'reject' { 
    firewall { '998 last input':
      action => $ipv4_action,
      chain  => 'INPUT',
      proto  => 'all',
      reject => $ipv4_reject_with,
      before => undef,
    }
    firewall { '999 last forward':
      action => $ipv4_action,
      chain  => 'FORWARD',
      proto  => 'all',
      reject => $ipv4_reject_with,
      before => undef,
    }
  }
  else {
    firewall { '998 last input':
      action => $ipv4_action,
      chain  => 'INPUT',
      proto  => 'all',
      before => undef,
    }
    firewall { '999 last forward':
      action => $ipv4_action,
      chain  => 'FORWARD',
      proto  => 'all',
      before => undef,
    }
  }

  firewallchain { 'INPUT:filter:IPv4':
    ensure => 'present',
    policy => $ipv4_chain_action,
    before => undef,
  }
  firewallchain { 'FORWARD:filter:IPv4':
    ensure => 'present',
    policy => $ipv4_chain_action,
    before => undef,
  }

  if $ipv6 {
    if $ipv6_action == 'reject' { $ipv6_reject = $ipv6_reject_with }
    firewall { '998 last input ipv6':
      action   => $ipv6_action,
      chain    => 'INPUT',
      proto    => 'all',
      provider => 'ip6tables',
      reject   => $ipv6_reject,
    }
    firewall { '999 last forward ipv6':
      action   => $ipv6_action,
      chain    => 'FORWARD',
      proto    => 'all',
      provider => 'ip6tables',
      reject   => $ipv6_reject,
    }
    firewallchain { 'INPUT:filter:IPv6':
      ensure => 'present',
      policy => $ipv6_chain_action,
      before => undef,
    }
    firewallchain { 'FORWARD:filter:IPv6':
      ensure => 'present',
      policy => $ipv6_chain_action,
      before => undef,
    }
  }

}

