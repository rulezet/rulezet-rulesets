rule Trojan_Win32_Azorult_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 7c 24 10 89 6c 24 18 8b 44 24 24 01 44 24 18 8b 44 24 38 90 01 44 24 18 8b 44 24 18 89 44 24 20 8b 4c 24 1c 8b 44 24 20 8b d6 d3 ea 8b 4c 24 10 50 51 03 d3 89 54 24 1c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}