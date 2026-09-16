rule Webshell_r57shell_2b_RID2E8F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell R57"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 11:19:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e46777e5f1ac1652db3ce72dd0a2475ea515b37a737fffd743126772525a47e6"
      hash2 = "aa957ca4154b7816093d667873cf6bdaded03f820e84d8f1cd5ad75296dd5d4d"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$connection = @ftp_connect($ftp_server,$ftp_port,10);" fullword ascii
      $s2 = "echo $lang[$language.'_text98'].$suc.\"\\r\\n\";" fullword ascii
   condition: 
      filesize < 900KB and all of them
}