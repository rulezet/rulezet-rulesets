rule TrojanSpy_Win32_Bafi_Q{
	meta:
		description = "TrojanSpy:Win32/Bafi.Q,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 db 33 c0 99 8a 11 80 ca 20 03 c2 8d 49 02 66 39 19 75 ?? 3d e0 1e 00 00 75 ?? c7 44 3c ?? 01 00 00 80 c7 05 ?? ?? ?? ?? 01 00 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}