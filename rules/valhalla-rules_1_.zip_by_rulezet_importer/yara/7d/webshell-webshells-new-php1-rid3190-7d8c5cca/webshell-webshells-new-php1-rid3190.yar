rule Webshell_webshells_new_PHP1_RID3190 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file PHP1.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:27:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<[url=mailto:?@array_map($_GET[]?@array_map($_GET['f'],$_GET[/url]);?>" fullword
      $s2 = ":https://forum.90sec.org/forum.php?mod=viewthread&tid=7316" fullword
      $s3 = "@preg_replace(\"/f/e\",$_GET['u'],\"fengjiao\"); " fullword
   condition: 
      1 of them
}