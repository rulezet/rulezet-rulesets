rule apt_hellsing_irene { 
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing msger irene installer"
		id = "b57d1a10-4e5c-511f-b98c-8ce7d766c227"
	strings: 
		$a1 = "\\Drivers\\usbmgr.tmp" wide
		$a2 = "\\Drivers\\usbmgr.sys" wide
		$a3 = "common_loadDriver CreateFile error!"
		$a4 = "common_loadDriver StartService error && GetLastError():%d!"
		$a5 = "irene" wide
		$a6 = "aPLib v0.43 - the smaller the better" 
	condition:
		uint16(0) == 0x5a4d and (4 of ($a*)) and filesize < 500000
}