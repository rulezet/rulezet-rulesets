rule Webshell_queryDong_spyjsp2010_zend_RID343F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, config.jsp, myxx.jsp, queryDong.jsp, spyjsp2010.jsp, zend.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:22:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "059058a27a7b0059e2c2f007ad4675ef"
      hash2 = "8b457934da3821ba58b06a113e0d53d9"
      hash3 = "d44df8b1543b837e57cc8f25a0a68d92"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "return new Double(format.format(value)).doubleValue();" fullword
      $s5 = "File tempF = new File(savePath);" fullword
      $s9 = "if (tempF.isDirectory()) {" fullword
   condition: 
      2 of them
}