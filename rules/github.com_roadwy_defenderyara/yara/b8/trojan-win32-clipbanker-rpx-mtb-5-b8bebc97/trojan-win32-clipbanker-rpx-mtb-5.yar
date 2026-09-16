rule Trojan_Win32_ClipBanker_RPX_MTB_5{
	meta:
		description = "Trojan:Win32/ClipBanker.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 84 35 08 fe ff ff 88 84 3d 08 fe ff ff 88 8c 35 08 fe ff ff 0f b6 84 3d 08 fe ff ff 8b 8d 9c fc ff ff 03 c2 0f b6 c0 0f b6 84 05 08 fe ff ff 32 44 0d bc 88 84 0d a0 fd ff ff 41 89 8d 9c fc ff ff 83 f9 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}