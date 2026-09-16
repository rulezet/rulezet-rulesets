rule Webshell_laudanum_RID2DFD : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file laudanum.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 10:55:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "public function __activate()" fullword ascii
      $s2 = "register_activation_hook(__FILE__, array('WP_Laudanum', 'activate'));" fullword ascii
   condition: 
      filesize < 5KB and all of them
}