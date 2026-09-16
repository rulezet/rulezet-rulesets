rule Webshell_webshells_new_JSP_RID3164 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file JSP.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:20:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "void AA(StringBuffer sb)throws Exception{File r[]=File.listRoots();for(int i=0;i" 
      $s5 = "bw.write(z2);bw.close();sb.append(\"1\");}else if(Z.equals(\"E\")){EE(z1);sb.app" 
      $s11 = "if(Z.equals(\"A\")){String s=new File(application.getRealPath(request.getRequest" 
   condition: 
      1 of them
}