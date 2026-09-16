rule Trojan_Win32_Ekstak_RC_MTB_7{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 0c 57 68 70 0a 4d 00 e8 1f ed fc ff b9 41 00 00 00 33 c0 bf 00 06 4d 00 f3 ab } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}