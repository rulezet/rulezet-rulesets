rule EXPL_Exchange_ProxyNotShell_Patterns_CVE_2022_41040_Oct22_1_RID3B59 : CVE_2022_41040 DEMO EXPLOIT SCRIPT {
   meta:
      description = "Detects successful ProxyNotShell exploitation attempts in log files (attempt to identify the attack before the official release of detailed information)"
      author = "Florian Roth"
      reference = "https://github.com/kljunowsky/CVE-2022-41040-POC"
      date = "2022-10-11 20:25:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-03-15"
      tags = "CVE_2022_41040, DEMO, EXPLOIT, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $sr1 = / \/autodiscover\/autodiscover\.json[^\n]{1,300}owershell/ nocase ascii
      $sa1 = " 200 " 
      $fp1 = " 444 " 
      $fp2 = " 404 " 
      $fp2b = " 401 " 
      $fp3 = "GET /owa/ &Email=autodiscover/autodiscover.json%3F@test.com&ClientId=" ascii
      $fp4 = "@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com" ascii
   condition: 
      $sr1 and 1 of ( $sa* ) and not 1 of ( $fp* )
}