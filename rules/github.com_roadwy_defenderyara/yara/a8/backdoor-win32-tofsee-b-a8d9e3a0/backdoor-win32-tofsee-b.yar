rule Backdoor_Win32_Tofsee_B{
	meta:
		description = "Backdoor:Win32/Tofsee.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 85 58 ff ff ff 50 ff 75 f4 be ?? ?? ?? 00 89 5d b0 89 5d b4 89 75 a8 89 5d ac ff 15 ?? ?? 40 00 85 c0 0f 8c ?? 02 00 00 53 8d 45 b0 50 56 68 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}