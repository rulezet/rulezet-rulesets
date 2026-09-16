rule RogueFakeReanInternetSecuritySample
{
	meta:
		Description  = "Rogue.FakeRean.sm"
		ThreatLevel  = "5"

	strings:
		$ = "VB82ea936a-6aa61dbf" ascii wide
		$ = "VBOX HARDDISK" ascii wide
		$ = "avbase.dat" ascii wide
		$ = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
		$ = "ORDER #:" ascii wide
		$ = "Thank you, the program is now registered!" ascii wide
		$ = "To continue please restart the program. Press OK to close the program." ascii wide
		$ = "Wrong activation code! Please check and retry" ascii wide
		$ = "license. As soon as you complete the activation you will" ascii wide
		$ = "This option is available only in the activated version of " ascii wide
		$ = "You must activate the program by entering registration information " ascii wide
		$ = "has detected that a new Threat Database is available." ascii wide
		$ = "items are critical privacy compromising content"
		$ = "items is medium privacy threats" ascii wide
		$ = "items are junk content of low privacy threats" ascii wide
		$ = "has detected a leak of your files though the Internet. " ascii wide
		$ = "We strongly recommend that you block the attack immediately" ascii wide
		$ = "All threats has been succesfully removed." ascii wide
		$ = "Attention! We strongly recommend that you activate " ascii wide
		$ = "for the safety and faster running of your PC." ascii wide
		$ = "No new update available" ascii wide
		$ = "Could not connect to server!" ascii wide
		$ = "New updates are installed successfully!" ascii wide
		$ = "Security Warning!" ascii wide
		$ = "Malicious program has been detected." ascii wide
		$ = "Click here to protect your computer." ascii wide
		$ = "is infected by W32/Blaster.worm" ascii wide
		$ = "$$$$$$$$.bat" ascii wide
		$ = "Completed!" ascii wide
		$ = "Antivirus software uninstalled successfully" ascii wide
		$ = "Antivirus uninstall is not success. Please try again..." ascii wide
		$ = "-uninstall" ascii wide
		$ = "_MUTEX" ascii wide
		$ = "/min" ascii wide
		
	condition:
		7 of them
}