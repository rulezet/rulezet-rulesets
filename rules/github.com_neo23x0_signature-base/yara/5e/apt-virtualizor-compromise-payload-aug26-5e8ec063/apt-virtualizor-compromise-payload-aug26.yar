rule APT_Virtualizor_Compromise_Payload_Aug26 {
   meta:
      description = "Detects java based payload used in a campaign against compromised hosting providers using Virtualizor software"
      author = "Jonathan Peters (cod3nym)"
      date = "2026-08-31"
      reference = "https://lowendtalk.com/discussion/220625/urgent-virtualizor-compromised-31st-aug/p1"
      hash = "b81a4e1fab9fc4e404d57224fe71e2c143aa93942bd46998789bdc944a7870c7"
      score = 80
   strings:
      $s1 = "net/ikvm/clientvds/stresser/methods/impl/l4/minecraft/protocollib/" ascii
      $s2 = "oshi/util/VirtualizationDetector" ascii
      $s3 = "META-INF/proguard/base.proUT" ascii
   condition:
      uint16(0) == 0x4b50
      and filesize < 20MB
      and all of them
}