rule APT_WebShell_AUS_5_RID2D47 : APT DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18 10:25:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "54a17fb257db2d09d61af510753fd5aa00537638a81d0a8762a5645b4ef977e4"
      tags = "APT, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "function DEC(d){return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(d));}" fullword ascii
      $a2 = "function ENC(d){return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(d));}" fullword ascii
      $s1 = "var hash=DEC(Request.Item['" ascii
      $s2 = "Response.Write(ENC(SET_ASS_SUCCESS));" fullword ascii
      $s3 = "hashtable[hash] = assCode;" fullword ascii
      $s4 = "Response.Write(ss);" fullword ascii
      $s5 = "var hashtable = Application[CachePtr];" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x7566 and filesize < 2KB and 4 of them
}