rule EXPL_Exchange_ProxyShell_Failed_Aug21_1_RID3558 : DEMO EXPLOIT SCRIPT {
   meta:
      description = "Detects ProxyShell exploitation attempts in log files"
      author = "Florian Roth"
      reference = "https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html"
      date = "2021-08-08 16:09:11"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2021-08-09"
      tags = "DEMO, EXPLOIT, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $xr1 = / \/autodiscover\/autodiscover\.json[^\n]{1,300}\/(powershell|mapi\/nspi|EWS\/|X-Rps-CAT)[^\n]{1,400}401 0 0/ nocase ascii
      $xr3 = /Email=autodiscover\/autodiscover\.json[^\n]{1,400}401 0 0/ nocase ascii
   condition: 
      1 of them
}