rule EXPL_POC_SpringCore_0day_Webshell_Mar22_1_RID35BB : DEMO EXPLOIT SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects webshell found after SpringCore exploitation attempts POC script"
      author = "Florian Roth"
      reference = "https://twitter.com/vxunderground/status/1509170582469943303"
      date = "2022-03-30 16:25:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXPLOIT, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = ".getInputStream(); int a = -1; byte[] b = new byte[2048];" 
      $x2 = "if(\"j\".equals(request.getParameter(\"pwd\")" 
      $x3 = ".getRuntime().exec(request.getParameter(\"cmd\")).getInputStream();" 
   condition: 
      filesize < 200KB and 1 of them
}