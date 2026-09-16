rule Trojan_Win32_Stealc_RG_MTB{
	meta:
		description = "Trojan:Win32/Stealc.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 4c 24 30 91 e9 d1 5b 83 c4 0c 69 ed 91 e9 d1 5b 83 c6 04 8b c1 c1 e8 18 33 c1 69 c0 91 e9 d1 5b 33 e8 89 44 24 24 83 ef 01 75 c0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}