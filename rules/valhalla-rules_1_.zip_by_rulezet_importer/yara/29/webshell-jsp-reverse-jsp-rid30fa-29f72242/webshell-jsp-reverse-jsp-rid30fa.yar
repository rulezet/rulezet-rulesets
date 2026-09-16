rule Webshell_jsp_reverse_jsp_RID30FA : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files jsp-reverse.jsp, jsp-reverse.jsp, jspbd.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:02:51"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ea87f0c1f0535610becadf5a98aca2fc"
      hash2 = "7d5e9732766cf5b8edca9b7ae2b6028f"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "osw = new BufferedWriter(new OutputStreamWriter(os));" fullword
      $s7 = "sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());" fullword
      $s9 = "isr = new BufferedReader(new InputStreamReader(is));" fullword
   condition: 
      all of them
}