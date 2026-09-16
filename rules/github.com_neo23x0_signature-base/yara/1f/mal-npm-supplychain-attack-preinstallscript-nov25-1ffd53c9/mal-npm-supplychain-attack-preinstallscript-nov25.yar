rule MAL_NPM_SupplyChain_Attack_PreInstallScript_Nov25 {
   meta:
      description = "Detects known malicious preinstall script in package.json"
      author = "Marius Benthin"
      date = "2025-11-24"
      reference = "https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains"
      hash = "c4bc2afd133916f064f2fb7d1e2e067ea65db33463eeae2fa54a9860a6303865"
      score = 80
   strings:
      $x1 = "\"preinstall\": \"node setup_bun.js\""
   condition:
      filesize < 10KB
      and all of them
}