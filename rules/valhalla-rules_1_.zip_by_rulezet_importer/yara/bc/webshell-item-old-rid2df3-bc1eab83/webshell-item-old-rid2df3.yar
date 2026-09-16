rule Webshell_item_old_RID2DF3 : CHINA DEMO T1105 T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file item-old.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:53:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1105, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
      $s2 = "$sCmd = \"convert \".$sFile.\" -flip -quality 80 \".$sFileOut;" fullword ascii
      $s3 = "$sHash = md5($sURL);" fullword ascii
   condition: 
      filesize < 7KB and 2 of them
}