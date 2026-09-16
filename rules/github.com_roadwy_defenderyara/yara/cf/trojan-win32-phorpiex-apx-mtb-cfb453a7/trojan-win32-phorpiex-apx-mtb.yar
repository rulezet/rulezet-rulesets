rule Trojan_Win32_Phorpiex_APX_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.APX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 8b 4d 10 51 8b 55 0c 52 8b 45 08 50 68 ?? ?? ?? ?? 8d 8d 00 fe ff ff 51 ff 15 ?? ?? ?? ?? 83 c4 14 6a 00 6a 00 6a 00 6a 00 68 88 41 40 00 ff 15 } 		$a_01_1 = {31 37 38 2e 31 36 2e 35 34 2e 31 30 39 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}