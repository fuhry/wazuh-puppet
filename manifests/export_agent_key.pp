#Export agent key
class wazuh::export_agent_key(
  $max_clients,
  $agent_name,
  $agent_ip_address,
  $agent_seed,
  ) {
  if $::foreman_api_user != undef and $::foreman_api_password != undef {
    $host_info = foreman({
      foreman_user => $::foreman_api_user,
      foreman_pass => $::foreman_api_password,
      item         => "v2/hosts/${::fqdn}",
    })

    $agent_id = $host_info['id']
  }
  else {
    notify { "Using unsafe (collision-prone) fqdn_rand() to generate agent_id": }
    $agent_id = fqdn_rand($max_clients)
  }

  wazuh::agentkey{ "ossec_agent_${agent_name}_client":
    agent_id         => $agent_id,
    agent_name       => $agent_name,
    agent_ip_address => $agent_ip_address,
    agent_seed       => $agent_seed,
  }

  @@wazuh::agentkey{ "ossec_agent_${agent_name}_server":
    agent_id         => $agent_id,
    agent_name       => $agent_name,
    agent_ip_address => $agent_ip_address,
    agent_seed       => $agent_seed,
  }
}
