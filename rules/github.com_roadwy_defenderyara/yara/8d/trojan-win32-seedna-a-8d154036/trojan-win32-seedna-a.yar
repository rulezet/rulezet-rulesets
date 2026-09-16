rule Trojan_Win32_Seedna_A{
	meta:
		description = "Trojan:Win32/Seedna.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {3f 25 73 3d 25 73 26 25 73 3d 25 6c 64 26 25 73 3d 25 64 26 25 73 3d 25 [0-02] 26 25 73 3d 25 73 26 56 65 72 3d 53 25 73 } 		$a_01_1 = {0f b6 10 0f b6 48 01 8b f2 83 e6 0f 8b d9 c1 e6 02 c1 e9 06 0b ce } 		$a_01_2 = {8d 04 cd ff ff ff ff 99 6a 18 5b f7 fb 8d 04 85 04 00 00 00 39 45 14 0f 8c 8e 02 00 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}