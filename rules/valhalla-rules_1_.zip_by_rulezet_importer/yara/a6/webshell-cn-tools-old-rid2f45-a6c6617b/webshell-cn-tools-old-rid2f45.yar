rule Webshell_CN_Tools_old_RID2F45 : CHINA DEMO T1105 T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file old.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 11:50:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1105, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
      $s1 = "$sURL = \"http://\".$sServer.\"/\".$sFile;" fullword ascii
      $s2 = "chmod(\"/\".substr($sHash, 0, 2), 0777);" fullword ascii
      $s3 = "$sCmd = \"echo 123> \".$sFileOut;" fullword ascii
   condition: 
      filesize < 6KB and all of them
}