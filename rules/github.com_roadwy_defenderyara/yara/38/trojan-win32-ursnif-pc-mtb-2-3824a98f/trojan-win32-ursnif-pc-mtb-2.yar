rule Trojan_Win32_Ursnif_PC_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 1c 7f 2b dd c7 44 24 ?? 00 00 00 00 8d 0c 40 2b cb 0f b7 c9 bf 2a 00 00 00 2b f9 2b fd 03 c7 8b 3d ?? ?? ?? 00 8b 8c 37 ?? ?? ff ff 81 c1 64 c8 31 01 89 8c 37 ?? ?? ff ff 8d 7c 00 fb 0f b7 ff 89 7c 24 10 0f b7 ff 8d 94 2a 5c b3 fe ff 8b ef 2b ea 83 c6 04 8d 44 28 ?? a3 ?? ?? ?? 00 81 fe ?? ?? 00 00 0f 82 ?? ff ff ff } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}