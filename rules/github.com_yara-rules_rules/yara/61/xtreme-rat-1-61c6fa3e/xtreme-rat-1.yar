rule xtreme_rat_1
{ 
	meta:
		maltype = "Xtreme RAT"
		ref = "https://github.com/reed1713"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/xtreme-rat-targets-israeli-government/"
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="5156"
		$data="windows\\system32\\sethc.exe"

		$type1="Microsoft-Windows-Security-Auditing"
		$eventid1="4688"
		$data1="AppData\\Local\\Temp\\Microsoft Word.exe"
	condition:
		all of them
}