rule Ransom_Win32_Crowti_A{
	meta:
		description = "Ransom:Win32/Crowti.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 a0 00 00 00 e8 18 00 00 00 59 89 45 fc 83 7d fc 00 74 ?? 8b 45 fc 2d ?? ?? ?? ?? ff d0 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}