rule Trojan_Win32_StealC_A_MTB_2{
	meta:
		description = "Trojan:Win32/StealC.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 8b 45 f0 89 45 c8 8b 45 c8 8b 40 3c 8b 4d f0 8d 44 01 04 89 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}