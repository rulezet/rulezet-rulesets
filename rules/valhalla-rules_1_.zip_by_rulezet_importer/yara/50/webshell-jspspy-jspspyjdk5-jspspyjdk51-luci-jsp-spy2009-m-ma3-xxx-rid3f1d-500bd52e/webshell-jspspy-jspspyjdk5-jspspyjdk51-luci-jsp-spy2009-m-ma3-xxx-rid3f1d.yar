rule Webshell_JspSpy_JspSpyJDK5_JspSpyJDK51_luci_jsp_spy2009_m_ma3_xxx_RID3F1D : DEMO SCRIPT T1012 T1505_003 T1543_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 23:06:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "059058a27a7b0059e2c2f007ad4675ef"
      hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
      hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
      tags = "DEMO, SCRIPT, T1012, T1505_003, T1543_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "\"<form action=\\\"\"+SHELL_NAME+\"?o=upload\\\" method=\\\"POST\\\" enctype=" 
      $s9 = "<option value='reg query \\\"HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\T" 
   condition: 
      all of them
}