# Class: rhel::firewall
#
class rhel::firewall (
  $ipv6              = true,
  $icmp_limit        = false,
  $src_ssh           = [],
  $src_nrpe          = [],
  $ipv4_action       = 'reject',
  $ipv4_reject_with  = 'icmp-port-unreachable',
  $ipv6_action       = 'reject',
  $ipv6_reject_with  = 'icmp6-port-unreachable',
  $portknock         = {},
  $ipv4_chain_action = 'drop',
  $ipv6_chain_action = 'drop',
  $log_rejects       = true,
) {

  class { '::firewall': }

  # FIXME : Until the 'firewall::linux::redhat' class gets updated...
  if $ipv6 {
    service { 'ip6tables':
      ensure    => 'running',
      enable    => true,
      hasstatus => true,
    }
  }

  class { '::rhel::firewall::pre':
    ipv6       => $ipv6,
    icmp_limit => $icmp_limit,
  }

  # firewall doesn't support arrays for $source :-(
  # Take the opportunity to support a mix of IPv4/IPv6 in the array
  if $src_ssh and $src_ssh != [] {
    # a,b,c -> tcp_22_a,tcp_22_b,tcp_22_c
    $tcp_22_src = regsubst($src_ssh,'^(.+)$','tcp_22_\1')
    rhel::firewall::proto_dport_source { $tcp_22_src: prefix => '010' }
  }
  if $src_nrpe and $src_nrpe != [] {
    $tcp_5666_src = regsubst($src_nrpe,'^(.+)$','tcp_5666_\1')
    rhel::firewall::proto_dport_source { $tcp_5666_src: prefix => '011' }
  }

  class { '::rhel::firewall::post':
    ipv6              => $ipv6,
    ipv4_action       => $ipv4_action,
    ipv4_reject_with  => $ipv4_reject_with,
    ipv6_action       => $ipv6_action,
    ipv6_reject_with  => $ipv6_reject_with,
    ipv4_chain_action => $ipv4_chain_action,
    ipv6_chain_action => $ipv4_chain_action,
    log_rejects       => $log_rejects,
  }

  # Optional portknock resources to be created
  create_resources(rhel::firewall::portknock,$portknock)

}

