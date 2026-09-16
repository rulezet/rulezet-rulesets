rule Trojan_Win32_Rhadhamanthys_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Rhadhamanthys.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 f9 61 7c 0a 80 f9 66 7f 05 80 e9 57 eb 0d 80 f9 30 7c 0f 80 f9 39 7f 0a 80 e9 30 88 4c 14 0c 83 c2 01 83 fa 02 75 20 3b c5 73 27 8a 4c 24 0c c0 e1 04 0a 4c 24 0d 83 c0 01 88 4c 38 ff 33 d2 88 5c 24 0d 88 5c 24 0c 83 c6 01 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}