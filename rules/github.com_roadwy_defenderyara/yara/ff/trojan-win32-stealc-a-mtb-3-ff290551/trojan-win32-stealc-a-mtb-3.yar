rule Trojan_Win32_StealC_A_MTB_3{
	meta:
		description = "Trojan:Win32/StealC.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 14 56 57 8b 7d 08 33 f6 89 47 0c 39 75 10 76 15 8b } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}