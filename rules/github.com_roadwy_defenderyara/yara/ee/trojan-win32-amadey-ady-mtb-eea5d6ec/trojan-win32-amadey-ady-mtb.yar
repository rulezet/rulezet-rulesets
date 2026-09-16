rule Trojan_Win32_Amadey_ADY_MTB{
	meta:
		description = "Trojan:Win32/Amadey.ADY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 4d ed 0f b6 55 ed f7 da 88 55 ed 0f b6 45 ed f7 d0 88 45 ed 0f b6 4d ed 81 c1 ?? ?? ?? ?? 88 4d ed 0f b6 55 ed f7 da 88 55 ed 0f b6 45 ed 83 e8 0d 88 45 ed 8b 4d c8 8a 55 ed 88 54 0d 9c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}