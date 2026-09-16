rule Trojan_Win32_Smokeloader_GJJ_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GJJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 ed d3 2b 81 84 24 ?? ?? ?? ?? dc 08 20 39 81 6c 24 ?? 00 d3 54 57 81 6c 24 ?? 9b 3c e4 2c 81 6c 24 ?? 20 1d 72 30 81 6c 24 ?? 22 08 cd 2c 81 44 24 ?? d8 8e 04 41 81 6c 24 ?? 12 93 56 0c 81 44 24 ?? a5 74 dd 47 b8 6e 7e 7a 1b f7 64 24 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}