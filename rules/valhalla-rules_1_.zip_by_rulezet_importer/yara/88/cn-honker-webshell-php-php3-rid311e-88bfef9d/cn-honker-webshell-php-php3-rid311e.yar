rule CN_Honker_Webshell_PHP_php3_RID311E : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php3.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:08:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "} elseif(@is_resource($f = @popen($cfe,\"r\"))) {" fullword ascii
      $s2 = "cf('/tmp/.bc',$back_connect);" fullword ascii
   condition: 
      filesize < 8KB and all of them
}