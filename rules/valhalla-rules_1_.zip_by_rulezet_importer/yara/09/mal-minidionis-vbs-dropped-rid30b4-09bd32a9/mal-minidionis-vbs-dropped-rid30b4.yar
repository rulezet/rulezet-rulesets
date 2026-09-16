rule MAL_MiniDionis_VBS_Dropped_RID30B4 : DEMO MAL SCRIPT {
   meta:
      description = "Dropped File - 1.vbs"
      author = "Florian Roth"
      reference = "https://malwr.com/analysis/ZDc4ZmIyZDI4MTVjNGY5NWI0YzE3YjIzNGFjZTcyYTY/"
      date = "2015-07-21 12:51:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Wscript.Sleep 5000" ascii
      $s2 = "Set FSO = CreateObject(\"Scripting.FileSystemObject\")" ascii
      $s3 = "Set WshShell = CreateObject(\"WScript.Shell\")" ascii
      $s4 = "If(FSO.FileExists(\"" ascii
      $s5 = "then FSO.DeleteFile(\".\\" ascii
   condition: 
      filesize < 1KB and all of them and $s1 in ( 0 .. 40 )
}