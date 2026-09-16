rule Trojan_Win32_DiscordStealer_ARA_MTB{
	meta:
		description = "Trojan:Win32/DiscordStealer.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_80_0 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d } 		$a_80_1 = {53 65 74 75 70 3d 64 6f 65 6e 65 72 69 75 6d 2d 77 69 6e 2e 65 78 65 } 		$a_80_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1) >=5
 
}