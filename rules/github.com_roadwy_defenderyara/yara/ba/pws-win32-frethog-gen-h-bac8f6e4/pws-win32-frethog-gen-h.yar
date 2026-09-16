rule PWS_Win32_Frethog_gen_H{
	meta:
		description = "PWS:Win32/Frethog.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 03 01 00 00 50 56 ff 15 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 6a 5c 50 ff 15 ?? ?? ?? ?? 8b f8 8d 45 f4 50 c7 45 f4 7a 68 65 6e 8d 5f 01 c7 45 f8 67 74 75 2e 53 c7 45 fc 64 61 74 00 ff 15 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}