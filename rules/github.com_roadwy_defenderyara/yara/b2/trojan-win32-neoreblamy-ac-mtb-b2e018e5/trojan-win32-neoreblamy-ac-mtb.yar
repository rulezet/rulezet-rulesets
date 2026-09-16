rule Trojan_Win32_Neoreblamy_AC_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b fe 8b 74 24 1c 8b cb d3 ff 8b c7 8d 4c 24 20 33 c6 99 52 50 } 		$a_03_1 = {55 8b ec 83 e4 f8 83 ec 1c 53 c7 44 24 04 ?? ?? 00 00 81 7c 24 04 ?? ?? 00 00 56 57 } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}