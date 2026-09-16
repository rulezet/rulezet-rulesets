rule MAL_JS_NPM_SupplyChain_Compromise_Sep25_RID356B : DEMO FILE MAL T1059_007 {
   meta:
      description = "Detects a supply chain compromise in NPM packages (TinyColor, CrowdStrike etc.)"
      author = "Florian Roth"
      reference = "https://socket.dev/blog/tinycolor-supply-chain-attack-affects-40-packages"
      date = "2025-09-16 16:12:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, MAL, T1059_007"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "if (plat === \"linux\") return \"https://github.com/trufflesecurity/trufflehog/releases" 
      $sa1 = "curl -d \"$CONTENTS\" https://webhook.site/" ascii
      $sa2 = "curl -s -X POST -d \"$CONTENTS\" \"https://webhook.site/" 
      $sb1 = " | base64 -w 0 | " ascii
      $sb2 = " | base64 -w0)" 
   condition: 
      filesize < 20MB and ( 1 of ( $x* ) or ( 1 of ( $sa* ) and 1 of ( $sb* ) ) ) and not uint8 ( 0 ) == 0x7b
}