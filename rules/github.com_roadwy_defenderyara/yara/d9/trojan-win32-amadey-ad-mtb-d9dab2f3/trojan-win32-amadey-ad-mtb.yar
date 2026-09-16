rule Trojan_Win32_Amadey_AD_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 55 ff 0f b6 45 ff f7 d0 88 45 ff 0f b6 4d ff 03 4d 94 88 4d ff 0f b6 55 ff f7 da 88 55 ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}