rule Webshell_webshells_new_Asp_RID319B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file Asp.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:29:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Execute MorfiCoder(\")/*/z/*/(tseuqer lave\")" fullword
      $s2 = "Function MorfiCoder(Code)" fullword
      $s3 = "MorfiCoder=Replace(Replace(StrReverse(Code),\"/*/\",\"\"\"\"),\"\\*\\\",vbCrlf)" fullword
   condition: 
      1 of them
}