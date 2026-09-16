rule Trojan_Win32_Zenpack_RPY_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpack.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d fc 8b 91 ac 00 00 00 03 42 3c 8b 4d fc 6b 91 c8 04 00 00 28 8d 84 10 f8 00 00 00 8b 4d fc 89 81 b4 04 00 00 6a 00 8b 55 fc 8b 82 b4 04 00 00 8b 48 10 51 8b 4d fc 83 c1 0c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}