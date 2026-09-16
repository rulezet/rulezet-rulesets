rule obs_vbs_pwsh_comobj_manipulation {

meta: 
	sha = "561e3780b6c1d17074806312b5f77378d8a9ac8088cc44389fb8a7f1b73850eb"
	filename = "globalthings.hta"
	source = "Malwarebazaar"
	tags = "vbs, REMCOS, html, downloader, Trojan, dwnldr, obfuscated" 
		
strings:
	$a1 = /adodb\.StREAM/ nocase
	$a2 = /MsXMl2\.DoMDocuMENt/

	$p1 = "CReATeeLeMEnt" nocase
	$p2 = "bypASS" nocase
	$p3 = "PoWeRShEll" nocase
	$p4 = "-NOP -W" nocase

	$v1 = "cREateOBjEct" nocase
	$v2 = "exPAndeNvIronmENTStrings" nocase
	

condition:

	(all of ($a*)) and (3 of ($p*)) or (all of ($v*))
	
}