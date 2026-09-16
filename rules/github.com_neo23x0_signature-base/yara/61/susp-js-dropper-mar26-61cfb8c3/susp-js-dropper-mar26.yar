rule SUSP_JS_Dropper_Mar26 {
   meta:
      description = "Detects suspicious JavaScript dropper used in plain-crypto-js supply chain attacks"
      author = "Marius Benthin"
      date = "2026-03-31"
      reference = "https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan"
      hash = "e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09"
      score = 70
      id = "456a52c2-9cbf-572f-9a5b-b8d74183e3f4"
   strings:
      $sa1 = "Buffer.from("
      $sa2 = "FileSync("
      $sa3 = ".replaceAll("

      $sb1 = ".arch()"
      $sb2 = ".platform()"
      $sb3 = ".release()"
      $sb4 = ".type()"
   condition:
      filesize < 10KB
      and all of ($sa*)
      and 2 of ($sb*)
}