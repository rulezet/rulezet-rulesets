rule MAL_Grace_Dec22_RID2BFB : DEMO MAL {
   meta:
      description = "Detects Grace (aka FlawedGrace and GraceWire) RAT"
      author = "X__Junior"
      reference = "https://blog.talosintelligence.com/breaking-the-silence-recent-truebot-activity/"
      date = "2022-12-13 09:29:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a66df3454b8c13f1b92d8b2cf74f5bfcdedfbff41a5e4add62e15277d14dd169"
      hash2 = "e113a8df3c4845365f924bacf10c00bcc5e17587a204b640852dafca6db20404"
      tags = "DEMO, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $sa1 = "Grace finalized, no more library calls allowed." ascii
      $sa2 = "Socket forcibly closed due to no response to DISCONNECT signal from other side, worker id(%d)" ascii
      $sa3 = "AVWireCleanupThread" ascii
      $sa4 = "AVTunnelClientDirectIO" ascii
      $sa5 = "AVGraceTunnelWriteThread" ascii
      $sa6 = "AVGraceTunnelClientDirectIO" ascii
   condition: 
      2 of them
}