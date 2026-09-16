rule PWS_Win32_Qakbot_MFP_MTB{
	meta:
		description = "PWS:Win32/Qakbot.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 06 46 85 c0 74 ?? 57 29 3c e4 09 0c e4 52 c7 04 e4 ?? ?? ?? ?? 59 bb ?? ?? ?? ?? 56 8f 45 f4 ff 75 f4 5a c7 45 fc ?? ?? ?? ?? d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 ?? 57 33 3c e4 09 df 83 e0 00 09 f8 5f 81 e1 00 00 00 00 33 0c e4 83 ec ?? aa 49 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}