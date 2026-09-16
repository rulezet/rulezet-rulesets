rule CN_Honker_Webshell_PHP_php7_RID3122 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php7.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:09:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "---> '.$ports[$i].'<br>'; ob_flush(); flush(); } } echo '</div>'; return true; }" ascii
      $s1 = "$getfile = isset($_POST['downfile']) ? $_POST['downfile'] : ''; $getaction = iss" ascii
   condition: 
      filesize < 300KB and all of them
}