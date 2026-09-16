rule JSP_jfigueiredo_APT_webshell_RID31E3 : APT DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
      author = "Florian Roth"
      reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/Browser.jsp"
      date = "2014-10-12 13:41:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "String fhidden = new String(Base64.encodeBase64(path.getBytes()));" ascii
      $a2 = "<form id=\"upload\" name=\"upload\" action=\"ServFMUpload\" method=\"POST\" enctype=\"multipart/form-data\">" ascii
   condition: 
      all of them
}