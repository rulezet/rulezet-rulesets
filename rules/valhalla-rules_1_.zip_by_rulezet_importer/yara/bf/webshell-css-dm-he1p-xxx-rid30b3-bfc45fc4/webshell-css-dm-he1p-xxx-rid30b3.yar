rule Webshell_css_dm_he1p_xxx_RID30B3 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:51:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "059058a27a7b0059e2c2f007ad4675ef"
      hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
      hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "String savePath = request.getParameter(\"savepath\");" fullword
      $s4 = "URL downUrl = new URL(downFileUrl);" fullword
      $s5 = "if (Util.isEmpty(downFileUrl) || Util.isEmpty(savePath))" fullword
      $s6 = "String downFileUrl = request.getParameter(\"url\");" fullword
      $s7 = "FileInputStream fInput = new FileInputStream(f);" fullword
      $s8 = "URLConnection conn = downUrl.openConnection();" fullword
      $s9 = "sis = request.getInputStream();" fullword
   condition: 
      4 of them
}