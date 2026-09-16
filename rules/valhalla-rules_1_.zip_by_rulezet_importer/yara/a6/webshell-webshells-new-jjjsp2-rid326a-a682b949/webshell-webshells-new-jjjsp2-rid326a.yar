rule Webshell_webshells_new_JJJsp2_RID326A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file JJJsp2.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 14:04:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "QQ(cs, z1, z2, sb,z2.indexOf(\"-to:\")!=-1?z2.substring(z2.indexOf(\"-to:\")+4,z" 
      $s8 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()+ \"\\t\" + sQ" 
      $s10 = "ResultSet r = s.indexOf(\"jdbc:oracle\")!=-1?c.getMetaData()" 
      $s11 = "return DriverManager.getConnection(x[1].trim()+\":\"+x[4],x[2].equalsIgnoreCase(" 
   condition: 
      1 of them
}