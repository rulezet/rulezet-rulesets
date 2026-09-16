rule WEBSHELL_H4ntu_Shell_Powered_Tsoi {
   meta:
      description = "Semi-Auto-generated - file h4ntu shell [powered by tsoi].txt"
      author = "Florian Roth"
      date = "2014-03-29"
      modified = "2025-03-21"
      score = 80
      old_rule_name = "Webshell_h4ntu_shell__powered_by_tsoi_"
      hash = "06ed0b2398f8096f1bebf092d0526137"
   strings:
      $x1 = "<title>h4ntu shell"
      $x2 = "system(\"$cmd 1> /tmp/cmdtemp 2>&1; cat /tmp/cmdtemp; rm /tmp/cmdtemp\");"
   condition:
      filesize < 100KB
      and 1 of them
}