rule Trojan_Win32_Zusy_AC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8b 4d fc 8b 75 08 8b 4c 8e 20 89 8c 10 00 10 00 00 8b 55 fc 8b 45 08 8b 8d 28 ff ff ff 33 4c ?? 20 ba 04 00 00 00 c1 e2 03 8b 45 0c 89 0c 10 b9 04 00 00 00 6b d1 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}