rule MAL_JS_NPM_SupplyChain_Attack_Nov25_RID33B0 : DEMO MAL T1059_007 {
   meta:
      description = "Detects malicious JavaScript worm bun_environment.js"
      author = "Marius Benthin"
      reference = "https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains"
      date = "2025-11-24 14:58:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-12-15"
      tags = "DEMO, MAL, T1059_007"
      minimum_yara = "3.5.0"
      
   strings:
      $sa1 = "npm publish" 
      $sa2 = "NPM_TOKEN" 
      $sa3 = "NPM_CONFIG_TOKEN" 
      $sb1 = "GITHUB_" 
      $sb2 = "GITLAB_" 
      $sb3 = "TEAMCITY_" 
   condition: 
      filesize < 20MB and all of ( $sa* ) and 2 of ( $sb* )
}