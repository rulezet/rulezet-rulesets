rule Trojan_Win32_Fragtor_NF_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 0d 53 e8 ?? ?? ?? ?? 59 85 c0 75 a9 eb 07 e8 ?? ?? ?? ?? 89 30 e8 d4 0e 00 00 89 30 8b c7 5f } 		$a_01_1 = {57 6b 56 32 31 54 53 61 76 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}