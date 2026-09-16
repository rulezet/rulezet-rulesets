rule MAL_NPM_SupplyChain_Attack_Mar26 {
   meta:
      description = "Detects package.json which include the malicious plain-crypto-js package as dependency"
      author = "Marius Benthin"
      date = "2026-03-31"
      reference = "https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan"
      hash = "5e3e89c7351f385e36bb70286866a62957cc1aaab195539edb8c7bb62968a137"
      score = 80
      id = "88e7af97-f7c1-591e-960c-d5296da94066"
   strings:
      $s1 = "\"dependencies\":"
            $s2 = { 22 70 6C 61 69 6E 2D 63 72 79 70 74 6F 2D 6A 73 22 3A [0-3] 22 [0-2] 34 2E 32 2E }     condition:
      filesize < 10KB
      and all of them
}