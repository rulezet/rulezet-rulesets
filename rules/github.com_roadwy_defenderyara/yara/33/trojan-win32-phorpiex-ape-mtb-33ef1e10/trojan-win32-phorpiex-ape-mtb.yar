rule Trojan_Win32_Phorpiex_APE_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.APE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 8d 85 00 fe ff ff 50 e8 ?? ?? ?? ?? 83 c4 0c 68 00 21 40 00 8d 8d 00 fe ff ff 51 ff 15 ?? ?? ?? ?? 83 c4 08 6a 00 6a 00 6a 00 6a 00 68 20 21 40 00 ff 15 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}