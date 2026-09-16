rule EXPL_Exchange_ProxyShell_Successful_Aug21_1_RID3733 : DEMO EXPLOIT SCRIPT {
   meta:
      description = "Detects successful ProxyShell exploitation attempts in log files"
      author = "Florian Roth"
      reference = "https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html"
      date = "2021-08-08 17:28:21"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-03-21"
      tags = "DEMO, EXPLOIT, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $xr1a = / \/autodiscover\/autodiscover\.json[^\n]{1,300}\/(powershell|X-Rps-CAT)/ nocase ascii
      $xr1b = / \/autodiscover\/autodiscover\.json[^\n]{1,300}\/(mapi\/nspi|EWS\/)[^\n]{1,400}(200|302) 0 0/ 
      $xr2 = /autodiscover\/autodiscover\.json[^\n]{1,60}&X-Rps-CAT=/ nocase ascii
      $xr3 = /Email=autodiscover\/autodiscover\.json[^\n]{1,400}200 0 0/ nocase ascii
   condition: 
      1 of them
}