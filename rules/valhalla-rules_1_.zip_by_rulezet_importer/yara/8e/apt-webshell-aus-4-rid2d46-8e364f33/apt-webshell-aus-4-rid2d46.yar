rule APT_WebShell_AUS_4_RID2D46 : APT DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18 10:24:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "83321c02339bb51735fbcd9a80c056bd3b89655f3dc41e5fef07ca46af09bb71"
      tags = "APT, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "wProxy.Credentials = new System.Net.NetworkCredential(pusr, ppwd);" fullword ascii
      $s2 = "{return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(" ascii
      $s3 = ".Equals('User-Agent', StringComparison.OrdinalIgnoreCase))" ascii
      $s4 = "gen.Emit(System.Reflection.Emit.OpCodes.Ret);" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x7566 and filesize < 10KB and 3 of them
}