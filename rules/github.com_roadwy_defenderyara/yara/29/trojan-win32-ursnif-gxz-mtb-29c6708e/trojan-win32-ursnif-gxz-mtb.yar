rule Trojan_Win32_Ursnif_GXZ_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 8b 45 f8 8b 00 83 e1 01 c1 e1 03 d3 e0 01 05 ?? ?? ?? ?? ff 4d fc ?? ?? ff 75 f4 ff 15 ?? ?? ?? ?? ff 75 fc 83 45 f8 04 ff 75 f4 ff 15 ?? ?? ?? ?? 3d 02 01 00 00 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}