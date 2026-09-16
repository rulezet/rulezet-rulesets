rule MAL_KHRAT_scritplet_RID2DFD : DEMO FILE MAL {
   meta:
      description = "Semiautomatically generated YARA rule - file MAL_KHRAT_scritplet_RID2DFD.sct"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/08/unit42-updated-khrat-malware-used-in-cambodia-attacks/"
      date = "2017-08-31 10:55:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cdb9104636a6f7c6018fe99bc18fb8b542689a84c23c10e9ea13d5aa275fd40e"
      tags = "DEMO, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "http.open \"POST\", \"http://update.upload-dropbox[.]com/docs/tz/GetProcess.php\",False,\"\",\"\" " fullword ascii
      $x2 = "Process=Process & Chr(32) & Chr(32) & Chr(32) & Obj.Description" fullword ascii
      $s1 = "http.SetRequestHeader \"Content-Type\", \"application/json\" " fullword ascii
      $s2 = "Dim http,WMI,Objs,Process" fullword ascii
      $s3 = "Set Objs=WMI.InstancesOf(\"Win32_Process\")" fullword ascii
      $s4 = "'WScript.Echo http.responseText " fullword ascii
   condition: 
      uint16 ( 0 ) == 0x3f3c and filesize < 1KB and ( 1 of ( $x* ) or 4 of them )
}