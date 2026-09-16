rule Trojan_Win32_Azorult_RPC_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d1 e0 0f be 4c 05 f4 c1 f9 02 03 d1 8b 45 ec 03 45 f8 88 10 8b 4d f8 83 c1 01 89 4d f8 ba 01 00 00 00 6b c2 03 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}