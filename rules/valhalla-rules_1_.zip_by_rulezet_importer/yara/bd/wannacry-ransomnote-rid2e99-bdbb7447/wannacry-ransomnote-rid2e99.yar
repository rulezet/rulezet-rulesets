rule WannaCry_RansomNote_RID2E99 : CRIME DEMO FILE MAL RANSOM {
   meta:
      description = "Detects WannaCry Ransomware Note"
      author = "Florian Roth"
      reference = "https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100"
      date = "2017-05-12 11:21:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "4a25d98c121bb3bd5b54e0b6a5348f7b09966bffeec30776e5a731813f05d49e"
      tags = "CRIME, DEMO, FILE, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "A:  Don't worry about decryption." fullword ascii
      $s2 = "Q:  What's wrong with my files?" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x3a51 and filesize < 2KB and all of them )
}