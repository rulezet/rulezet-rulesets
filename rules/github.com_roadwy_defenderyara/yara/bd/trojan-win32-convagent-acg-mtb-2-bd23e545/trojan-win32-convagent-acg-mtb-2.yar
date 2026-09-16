rule Trojan_Win32_Convagent_ACG_MTB_2{
	meta:
		description = "Trojan:Win32/Convagent.ACG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 54 34 28 0f b6 84 34 28 01 00 00 03 d8 0f b6 ca 03 d9 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 8a 44 1c 28 88 44 34 28 46 88 54 1c 28 81 fe } 		$a_01_1 = {0f b6 44 1c 28 88 44 34 28 88 4c 1c 28 0f b6 44 34 28 8b 4c 24 0c 03 c2 8b 54 24 10 0f b6 c0 0f b6 44 04 28 32 44 39 08 88 04 0a 41 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3) >=4
 
}