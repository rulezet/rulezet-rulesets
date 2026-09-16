rule Trojan_Win32_Tepfer_EM_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 3e 83 c3 04 83 c6 04 3b 5d e0 72 b1 b8 00 10 00 00 8b 55 e4 03 55 dc 2b d0 83 c2 04 89 55 ec } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}