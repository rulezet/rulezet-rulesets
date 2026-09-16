rule Trojan_Win32_Drixed_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Drixed.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 bd ff fe ff ff 54 89 85 f4 fe ff ff 75 4a 80 bd 00 ff ff ff 45 75 41 80 bd 01 ff ff ff 53 75 38 80 bd 02 ff ff ff 54 75 2f 80 bd 03 ff ff ff 41 75 26 80 bd 04 ff ff ff 50 75 1d 80 bd 05 ff ff ff 50 75 14 b8 01 00 00 00 80 bd 0a ff ff ff 00 89 85 f0 fe ff ff 74 0a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}