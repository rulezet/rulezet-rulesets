rule Suckfly_Nidiran_Gen_1_RID2F1F : DEMO EXE FILE G0039 GEN MAL {
   meta:
      description = "Detects Suckfly Nidiran Trojan"
      author = "Florian Roth"
      reference = "https://www.symantec.com/connect/blogs/suckfly-revealing-secret-life-your-code-signing-certificates"
      date = "2018-01-28 11:43:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ac7d7c676f58ebfa5def9b84553f00f283c61e4a310459178ea9e7164004e734"
      tags = "DEMO, EXE, FILE, G0039, GEN, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "WriteProcessMemory fail at %d " fullword ascii
      $s2 = "CreateRemoteThread fail at %d " fullword ascii
      $s3 = "CreateRemoteThread Succ" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 2 of them
}