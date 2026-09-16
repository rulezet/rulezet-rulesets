rule Webshell_AcidPoison_RID2E8F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Poison Sh3ll - Webshell"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 11:19:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
      hash3 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "elseif ( enabled(\"exec\") ) { exec($cmd,$o); $output = join(\"\\r\\n\",$o); }" fullword ascii
   condition: 
      filesize < 550KB and all of them
}