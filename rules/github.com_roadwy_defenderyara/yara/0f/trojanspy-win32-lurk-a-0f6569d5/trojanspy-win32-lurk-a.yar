rule TrojanSpy_Win32_Lurk_A{
	meta:
		description = "TrojanSpy:Win32/Lurk.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 33 c9 68 ?? ?? ?? ?? c3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}