rule Trojan_Win64_Cobaltstrike_DS_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 13 49 8b c8 f6 d2 4c 3b c7 73 17 0f 1f 00 0f b6 c1 40 2a c6 32 01 32 c2 88 01 49 03 cb 48 3b cf 72 ec 49 ff c0 48 ff c3 49 83 ea 01 75 d0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}