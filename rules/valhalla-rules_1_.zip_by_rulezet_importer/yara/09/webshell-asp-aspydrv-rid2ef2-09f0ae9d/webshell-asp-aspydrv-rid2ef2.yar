rule Webshell_ASP_aspydrv_RID2EF2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file aspydrv.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:36:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "<%=thingy.DriveLetter%> </td><td><tt> <%=thingy.DriveType%> </td><td><tt> <%=thi" 
   condition: 
      all of them
}