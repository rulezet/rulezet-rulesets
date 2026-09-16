rule QuarksPwDump_Gen_RID2D5E : DEMO GEN HKTL {
   meta:
      description = "Detects all QuarksPWDump versions"
      author = "Florian Roth"
      reference = "-"
      date = "2015-09-29 10:28:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2b86e6aea37c324ce686bd2b49cf5b871d90f51cec24476daa01dd69543b54fa"
      hash2 = "87e4c76cd194568e65287f894b4afcef26d498386de181f568879dde124ff48f"
      hash3 = "a59be92bf4cce04335bd1a1fcf08c1a94d5820b80c068b3efe13e2ca83d857c9"
      tags = "DEMO, GEN, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "OpenProcessToken() error: 0x%08X" fullword ascii
      $s2 = "%d dumped" fullword ascii
      $s3 = "AdjustTokenPrivileges() error: 0x%08X" fullword ascii
      $s4 = "\\SAM-%u.dmp" ascii
   condition: 
      all of them
}