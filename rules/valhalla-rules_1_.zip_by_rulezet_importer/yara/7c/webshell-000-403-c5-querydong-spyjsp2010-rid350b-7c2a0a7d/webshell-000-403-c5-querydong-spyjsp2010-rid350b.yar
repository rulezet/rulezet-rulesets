rule Webshell_000_403_c5_queryDong_spyjsp2010_RID350B : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:56:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "059058a27a7b0059e2c2f007ad4675ef"
      hash2 = "8b457934da3821ba58b06a113e0d53d9"
      hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "\" <select name='encode' class='input'><option value=''>ANSI</option><option val" 
      $s7 = "JSession.setAttribute(\"MSG\",\"<span style='color:red'>Upload File Failed!</spa" 
      $s8 = "File f = new File(JSession.getAttribute(CURRENT_DIR)+\"/\"+fileBean.getFileName(" 
      $s9 = "((Invoker)ins.get(\"vd\")).invoke(request,response,JSession);" fullword
   condition: 
      2 of them
}