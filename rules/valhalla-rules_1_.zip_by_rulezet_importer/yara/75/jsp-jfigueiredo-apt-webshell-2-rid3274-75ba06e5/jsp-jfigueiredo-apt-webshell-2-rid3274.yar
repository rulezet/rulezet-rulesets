rule JSP_jfigueiredo_APT_webshell_2_RID3274 : APT DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
      author = "Florian Roth"
      reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/"
      date = "2014-10-12 14:05:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "<div id=\"bkorotator\"><img alt=\"\" src=\"images/rotator/1.jpg\"></div>" ascii
      $a2 = "$(\"#dialog\").dialog(\"destroy\");" ascii
      $s1 = "<form id=\"form\" action=\"ServFMUpload\" method=\"post\" enctype=\"multipart/form-data\">" ascii
      $s2 = "<input type=\"hidden\" id=\"fhidden\" name=\"fhidden\" value=\"L3BkZi8=\" />" ascii
   condition: 
      all of ( $a* ) or all of ( $s* )
}