rule Trojan_Win32_Copak_BAF_MTB_2{
	meta:
		description = "Trojan:Win32/Copak.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {21 c8 8b 3f 41 29 c1 29 c0 81 e7 ff 00 00 00 29 c9 42 01 c9 21 c0 b9 ?? ?? ?? ?? 81 fa f4 01 00 00 75 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}