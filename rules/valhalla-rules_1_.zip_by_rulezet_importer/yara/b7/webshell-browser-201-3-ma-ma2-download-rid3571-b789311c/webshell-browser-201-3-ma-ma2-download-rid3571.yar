rule Webshell_browser_201_3_ma_ma2_download_RID3571 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, ma2.jsp, download.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 16:13:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a7e25b8ac605753ed0c438db93f6c498"
      hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
      hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "private static final int EDITFIELD_ROWS = 30;" fullword
      $s2 = "private static String tempdir = \".\";" fullword
      $s6 = "<input type=\"hidden\" name=\"dir\" value=\"<%=request.getAttribute(\"dir\")%>\"" 
   condition: 
      2 of them
}