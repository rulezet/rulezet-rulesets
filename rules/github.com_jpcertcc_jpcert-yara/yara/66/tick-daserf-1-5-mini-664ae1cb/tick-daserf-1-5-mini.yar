rule tick_daserf_1_5_mini {
    meta:
      description = "Daserf malware"
      author = "JPCERT/CC Incident Response Group"
      hash = "bba61cdb14574c7700d2622167cb06432cd3f97899fa52a0530b83780a6545b2"

  	strings:
    	$user_agent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; SV1)"
      $version = "n:1.5"
      $mini = "Mini"

    condition:
    	all of them
}