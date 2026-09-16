rule Webshell_ok_style_1_JspSpy_RID3168 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files he1p.jsp, JspSpy.jsp, nogfw.jsp, ok.jsp, style.jsp, 1.jsp, JspSpy.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:21:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d71716df5042880ef84427acee8b121e"
      hash2 = "344f9073576a066142b2023629539ebd"
      hash3 = "32dea47d9c13f9000c4c807561341bee"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\"\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>\"+" fullword
      $s4 = "out.println(\"<h2>File Manager - Current disk &quot;\"+(cr.indexOf(\"/\") == 0?" 
      $s7 = "String execute = f.canExecute() ? \"checked=\\\"checked\\\"\" : \"\";" fullword
      $s8 = "\"<td nowrap>\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>" 
   condition: 
      2 of them
}