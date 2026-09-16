rule SoakSoak_Infected_Wordpress_RID31D6 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects a SoakSoak infected Wordpress site https://blog.sucuri.net/2014/12/soaksoak-malware-compromises-100000-wordpress-websites.html"
      author = "Florian Roth"
      reference = "https://blog.sucuri.net/2014/12/soaksoak-malware-compromises-100000-wordpress-websites.html"
      date = "2014-12-15 13:39:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "wp_enqueue_script(\"swfobject\");" ascii fullword
      $s1 = "function FuncQueueObject()" ascii fullword
      $s2 = "add_action(\"wp_enqueue_scripts\", 'FuncQueueObject');" ascii fullword
   condition: 
      all of ( $s* )
}