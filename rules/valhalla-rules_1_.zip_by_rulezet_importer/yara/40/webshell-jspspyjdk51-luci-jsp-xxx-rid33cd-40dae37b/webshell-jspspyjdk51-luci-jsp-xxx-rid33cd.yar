rule Webshell_JspSpyJDK51_luci_jsp_xxx_RID33CD : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:03:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "059058a27a7b0059e2c2f007ad4675ef"
      hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
      hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "ports = \"21,25,80,110,1433,1723,3306,3389,4899,5631,43958,65500\";" fullword
      $s1 = "private static class VEditPropertyInvoker extends DefaultInvoker {" fullword
   condition: 
      all of them
}