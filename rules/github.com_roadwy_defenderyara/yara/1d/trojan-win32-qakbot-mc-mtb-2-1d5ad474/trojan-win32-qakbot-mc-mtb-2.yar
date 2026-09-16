rule Trojan_Win32_Qakbot_MC_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af da 8d 50 ff 33 d0 89 91 fc 00 00 00 8b 81 00 01 00 00 01 41 50 8b 81 ec 00 00 00 01 41 10 8b 81 80 00 00 00 8b 91 a8 00 00 00 88 1c 02 ff 81 80 00 00 00 8b 81 c0 00 00 00 2b 81 0c 01 00 00 35 ?? ?? ?? ?? 01 81 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}