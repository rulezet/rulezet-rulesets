rule Trojan_Win32_Swisyn_ASW_MTB{
	meta:
		description = "Trojan:Win32/Swisyn.ASW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 55 51 55 e8 ?? ?? ?? ?? 85 c0 75 0f 6a 10 68 ac ?? ba 00 68 3c ?? ba 00 55 ff d7 6a ff 8d 54 24 20 55 52 6a 02 ff d6 3b c5 } 		$a_03_1 = {8d 44 24 00 68 ec ?? ba 00 50 e8 ?? ?? ?? ?? 83 c4 08 8d 4c 24 00 6a 10 68 ac ?? ba 00 51 6a 00 ff 15 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}