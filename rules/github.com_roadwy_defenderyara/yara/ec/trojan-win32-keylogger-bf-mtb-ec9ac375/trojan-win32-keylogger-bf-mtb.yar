rule Trojan_Win32_KeyLogger_BF_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 e5 48 88 64 1d be 5a a9 ac af a6 4a be dc 59 e7 53 49 ad 35 70 8c 82 bc 3d 18 0b 96 b5 9b a2 72 ea 49 ad 78 } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}