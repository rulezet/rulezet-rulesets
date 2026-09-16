rule Trojan_Win32_Azorult_RPC_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 4d fc 8b 55 f0 8b 02 2b c1 8b 4d f0 89 01 8b 55 f4 8b 45 f0 8b 08 89 0a 8b 55 f0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}