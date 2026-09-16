rule Webshell_c99_generic_RID2EB7 : DEMO GEN T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated "
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:26:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
      tags = "DEMO, GEN, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "  if ($copy_unset) {foreach($sess_data[\"copy\"] as $k=>$v) {unset($sess_data[\"" 
      $s1 = "  if (file_exists($mkfile)) {echo \"<b>Make File \\\"\".htmlspecialchars($mkfile" 
      $s2 = "  echo \"<center><b>MySQL \".mysql_get_server_info().\" (proto v.\".mysql_get_pr" 
      $s3 = "  elseif (!fopen($mkfile,\"w\")) {echo \"<b>Make File \\\"\".htmlspecialchars($m" 
   condition: 
      all of them
}