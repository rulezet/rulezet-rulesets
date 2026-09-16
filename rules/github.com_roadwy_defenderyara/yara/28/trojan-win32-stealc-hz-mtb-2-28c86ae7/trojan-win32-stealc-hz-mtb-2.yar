rule Trojan_Win32_StealC_HZ_MTB_2{
	meta:
		description = "Trojan:Win32/StealC.HZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 04 24 83 2c 24 ?? 0f be 04 32 89 44 24 ?? 8b 04 24 31 44 24 ?? 8a 4c 24 ?? 88 0c 32 42 3b d7 7c } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}