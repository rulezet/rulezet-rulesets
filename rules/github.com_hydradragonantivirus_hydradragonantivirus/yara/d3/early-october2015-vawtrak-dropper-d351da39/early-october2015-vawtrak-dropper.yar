rule early_october2015_vawtrak_dropper{
	meta:
		author = "Kevin Perlow"
		SHA256 = "3d1e7e54db786c6aef572d1ef57ad1c26413aacbf2fd91eb700d469c550dd4df"
		SHA256 = "3ffbe191d9326f97db4ffaf6b294c166397bf1c77d28e2ab44d41fca511ce55b"
    reference = "https://www.youtube.com/watch?v=DdkLY99HgAA"
	strings:
		$VBA = { 00 41 74 74 72 69 62 75 74 00 } 		$rtf = { 2E 72 74 66}         $exe = {2E 65 78 65} 		$string1 = "TEMP$ 4"
		$string2 = /[0-9][0-9][0-9]\.rtf/
		$string3 = /[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]\.exe/
		$a = {d0 cf 11 e0}
		$string4 = /C:\\Aaa\\exe\\[0-9A-Za-z]*\.exe/
		$string5 =  /C:\\Users\\M\\AppData\\Local\\Temp\\[0-9A-Za-z]*\.exe/
		$string6 = "X:\\multiplexing\\limitations\\electr.pdb"
		$Dyreza = "C:\\Users\\Em\\AppData\\Local\\Temp\\w12.exe"
		$RSA = "This file is protected with RSA key." nocase
	condition:
		$a at 0 and $VBA and (($rtf and $exe) or 2 of ($string1,$string2,$string3) or 2 of ($string4,$string5,$string6) or 2 of ($Dyreza,$RSA))
}