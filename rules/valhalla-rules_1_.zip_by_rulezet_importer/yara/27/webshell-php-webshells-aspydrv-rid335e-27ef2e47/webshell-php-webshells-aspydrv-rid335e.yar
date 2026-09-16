rule WebShell_php_webshells_aspydrv_RID335E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file aspydrv.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:44:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files" 
      $s1 = "nPos = InstrB(nPosEnd, biData, CByteString(\"Content-Type:\"))" fullword
      $s3 = "Document.frmSQL.mPage.value = Document.frmSQL.mPage.value - 1" fullword
      $s17 = "If request.querystring(\"getDRVs\")=\"@\" then" fullword
      $s20 = "' ---Copy Too Folder routine Start" fullword
   condition: 
      3 of them
}