rule EXPL_POC_SpringCore_0day_Webshell_Mar22_1 {
   meta:
      description = "Detects webshell found after SpringCore exploitation attempts POC script"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/vxunderground/status/1509170582469943303"
      date = "2022-03-30"
      score = 70
      id = "e7047c98-3c60-5211-9ad5-2bfdfb35d493"
   strings:
      $x1 = ".getInputStream(); int a = -1; byte[] b = new byte[2048];"
      $x2 = "if(\"j\".equals(request.getParameter(\"pwd\")"
      $x3 = ".getRuntime().exec(request.getParameter(\"cmd\")).getInputStream();"
   condition:
     filesize < 200KB and 1 of them
}