rule MAL_KHRAT_script_RID2CB8 : DEMO MAL SCRIPT T1053_005 T1218_011 {
   meta:
      description = "Semiautomatically generated YARA rule - file MAL_KHRAT_scritpt.js"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/08/unit42-updated-khrat-malware-used-in-cambodia-attacks/"
      date = "2017-08-31 10:01:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8c88b4177b59f4cac820b0019bcc7f6d3d50ce4badb689759ab0966780ae32e3"
      tags = "DEMO, MAL, SCRIPT, T1053_005, T1218_011"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "CreateObject(\"WScript.Shell\").Run \"schtasks /create /sc MINUTE /tn" ascii
      $x2 = "CreateObject(\"WScript.Shell\").Run \"rundll32.exe javascript:\"\"\\..\\mshtml,RunHTMLApplication" ascii
      $x3 = "<registration progid=\"ff010f\" classid=\"{e934870c-b429-4d0d-acf1-eef338b92c4b}\" >" fullword ascii
   condition: 
      1 of them
}