rule Webshell_HYTop_DevPack_fso_RID311E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file fso.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 13:08:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<!-- PageFSO Below -->" 
      $s1 = "theFile.writeLine(\"<script language=\"\"vbscript\"\" runat=server>if request(\"\"\"&cli" 
   condition: 
      all of them
}