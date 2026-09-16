rule Trojan_Win32_NSISInject_RF_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 57 6a 00 ff [0-05] 56 6a 01 [0-20] b8 ab aa aa aa f7 e6 [0-03] c1 ea 03 [0-03] 8d 0c 52 c1 e1 02 2b c1 [0-02] 8a 80 ?? ?? ?? ?? 30 ?? 33 [0-03] 3b f7 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}