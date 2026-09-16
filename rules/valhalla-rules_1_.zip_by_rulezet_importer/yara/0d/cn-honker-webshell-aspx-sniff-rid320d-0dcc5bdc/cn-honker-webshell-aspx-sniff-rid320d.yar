rule CN_Honker_Webshell_ASPX_sniff_RID320D : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file sniff.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:48:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));" fullword ascii
      $s2 = "if (!logIt && my_s_smtp && (dport == 25 || sport == 25))" fullword ascii
   condition: 
      filesize < 91KB and all of them
}