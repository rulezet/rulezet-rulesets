rule Trojan_Win32_ClipBanker_GZZ_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {5b b3 cb 64 0a 6d ef 30 76 01 fb b5 8a 3d 27 19 0e e9 } 		$a_01_1 = {48 19 5a aa 31 36 12 58 3e 5f 1c b4 2f 50 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}