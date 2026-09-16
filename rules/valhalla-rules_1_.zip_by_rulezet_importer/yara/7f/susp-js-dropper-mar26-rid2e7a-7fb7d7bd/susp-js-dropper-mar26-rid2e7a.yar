rule SUSP_JS_Dropper_Mar26_RID2E7A : DEMO SUSP T1059_007 {
   meta:
      description = "Detects suspicious JavaScript dropper used in plain-crypto-js supply chain attacks"
      author = "Marius Benthin"
      reference = "https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan"
      date = "2026-03-31 11:16:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SUSP, T1059_007"
      minimum_yara = "3.5.0"
      
   strings:
      $sa1 = "Buffer.from(" 
      $sa2 = "FileSync(" 
      $sa3 = ".replaceAll(" 
      $sb1 = ".arch()" 
      $sb2 = ".platform()" 
      $sb3 = ".release()" 
      $sb4 = ".type()" 
   condition: 
      filesize < 10KB and all of ( $sa* ) and 2 of ( $sb* )
}