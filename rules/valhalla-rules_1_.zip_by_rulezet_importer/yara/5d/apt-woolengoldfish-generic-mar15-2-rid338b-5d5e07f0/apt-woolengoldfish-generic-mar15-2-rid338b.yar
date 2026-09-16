rule APT_WoolenGoldfish_Generic_Mar15_2_RID338B : APT DEMO G0130 GEN {
   meta:
      description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
      author = "Florian Roth"
      reference = "https://www.trendmicro.com/vinfo/us/security/news/cyber-attacks/operation-woolen-goldfish-when-kittens-go-phishing"
      date = "2015-03-25 14:52:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "47b1c9caabe3ae681934a33cd6f3a1b311fd7f9f"
      hash2 = "62172eee1a4591bde2658175dd5b8652d5aead2a"
      hash3 = "7fef48e1303e40110798dfec929ad88f1ad4fbd8"
      tags = "APT, DEMO, G0130, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "modules\\exploits\\littletools\\agent_wrapper\\release" ascii
   condition: 
      all of them
}