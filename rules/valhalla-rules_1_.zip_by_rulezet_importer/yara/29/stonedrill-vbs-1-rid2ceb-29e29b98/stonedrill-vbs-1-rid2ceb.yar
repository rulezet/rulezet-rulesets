rule StoneDrill_VBS_1_RID2CEB : APT DEMO MIDDLE_EAST SCRIPT {
   meta:
      description = "Detects malware from StoneDrill threat report"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      date = "2017-03-07 10:09:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0f4d608a87e36cb0dbf1b2d176ecfcde837070a2b2a049d532d3d4226e0c9587"
      tags = "APT, DEMO, MIDDLE_EAST, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "wmic /NameSpace:\\\\root\\default Class StdRegProv Call SetStringValue hDefKey = \"&H80000001\" sSubKeyName = \"Software\\Micros" ascii
      $x2 = "ping 1.0.0.0 -n 1 -w 20000 > nul" fullword ascii
      $s1 = "WshShell.CopyFile \"%COMMON_APPDATA%\\Chrome\\" ascii
      $s2 = "WshShell.DeleteFile \"%temp%\\" ascii
      $s3 = "WScript.Sleep(10 * 1000)" fullword ascii
      $s4 = "Set WshShell = CreateObject(\"Scripting.FileSystemObject\") While WshShell.FileExists(\"" ascii
      $s5 = " , \"%COMMON_APPDATA%\\Chrome\\" ascii
   condition: 
      ( filesize < 1KB and 1 of ( $x* ) or 2 of ( $s* ) )
}