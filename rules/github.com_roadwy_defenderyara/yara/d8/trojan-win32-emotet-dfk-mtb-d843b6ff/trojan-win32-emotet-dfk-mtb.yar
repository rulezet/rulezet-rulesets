rule Trojan_Win32_Emotet_DFK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {03 c1 99 8b ce f7 f9 8b 45 f0 83 4d fc ff 8a 4c 15 00 30 08 } 		$a_81_1 = {6f 55 70 51 6d 7a 45 4f 39 36 59 6f 77 6b 39 65 62 61 48 39 4d 30 41 72 48 4a 45 63 71 76 57 72 69 } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}