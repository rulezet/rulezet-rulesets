rule Webshell_Tools_2015_RID2DDE : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file 2015.jsp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:50:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Configbis = new BufferedInputStream(httpUrl.getInputStream());" fullword ascii
      $s4 = "System.out.println(Oute.toString());" fullword ascii
      $s5 = "String ConfigFile = Outpath + \"/\" + request.getParameter(\"ConFile\");" fullword ascii
      $s8 = "HttpURLConnection httpUrl = null;" fullword ascii
      $s19 = "Configbos = new BufferedOutputStream(new FileOutputStream(Outf));;" fullword ascii
   condition: 
      filesize < 7KB and all of them
}