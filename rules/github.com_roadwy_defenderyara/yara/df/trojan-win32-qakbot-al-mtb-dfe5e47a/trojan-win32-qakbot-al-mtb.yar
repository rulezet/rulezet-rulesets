rule Trojan_Win32_Qakbot_AL_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 47 4c 37 30 00 } 		$a_01_1 = {ac 02 c3 32 c3 c0 c8 08 aa 49 e9 } 		$a_03_2 = {8b 55 f0 68 50 3c 0a 60 68 5a 6e 00 00 6a 00 e8 ?? ?? ?? ?? 5a ff d0 e9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}