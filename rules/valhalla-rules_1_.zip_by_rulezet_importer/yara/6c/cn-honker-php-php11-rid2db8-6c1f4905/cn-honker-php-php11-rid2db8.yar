rule CN_Honker_PHP_php11_RID2DB8 : CHINA DEMO HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file php11.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:43:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<tr><td><b><?php if (!$win) {echo wordwrap(myshellexec('id'),90,'<br>',1);} else" ascii
      $s2 = "foreach (glob($_GET['pathtomass'].\"/*.htm\") as $injectj00) {" fullword ascii
      $s3 = "echo '[cPanel Found] '.$login.':'.$pass.\"  Success\\n\";" fullword ascii
   condition: 
      filesize < 800KB and all of them
}