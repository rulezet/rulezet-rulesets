rule Trojan_Win32_Neoreblamy_GPG_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 05 6a 07 59 cd 29 6a 01 68 15 00 00 40 6a 03 e8 cb 31 00 00 83 c4 0c 6a 03 e8 } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}