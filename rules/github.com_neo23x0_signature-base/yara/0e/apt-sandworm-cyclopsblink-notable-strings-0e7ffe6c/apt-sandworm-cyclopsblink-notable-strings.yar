rule APT_Sandworm_CyclopsBlink_notable_strings {
   meta:
      author = "NCSC"
      description = "Detects notable strings identified within the Cyclops Blink executable"
      hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
      hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
      reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
      date = "2022-02-23"
      id = "81ccf582-41f5-5fe5-8afc-e008e01289ff"
   strings:
            $proc_name1 = "[kworker/0:1]"
      $proc_name2 = "[kworker/1:1]"
            $dns_query = "POST /dns-query HTTP/1.1\x0d\x0aHost: dns.google\x0d\x0a"
            $iptables1 = "iptables -I %s -p tcp --dport %d -j ACCEPT &>/dev/null"
      $iptables2 = "iptables -D %s -p tcp --dport %d -j ACCEPT &>/dev/null"
            $sys_recon1 = "{\"ver\":\"%x\",\"mods\";["
      $sys_recon2 = "uptime: %lu mem_size: %lu mem_free: %lu"
      $sys_recon3 = "disk_size: %lu disk_free: %lu"
      $sys_recon4 = "hw: %02x:%02x:%02x:%02x:%02x:%02x"
            $testpath = "%s/214688dsf46"
            $confpath = "%s/rootfs_cfg"
            $downpath = "/var/tmp/a.tmp"
   condition:
      (uint32(0) == 0x464c457f) and (8 of them)
}