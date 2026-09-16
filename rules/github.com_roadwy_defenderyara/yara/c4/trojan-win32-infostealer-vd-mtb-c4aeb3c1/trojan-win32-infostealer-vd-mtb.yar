rule Trojan_Win32_InfoStealer_VD_MTB{
	meta:
		description = "Trojan:Win32/InfoStealer.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f3 0f 10 c9 f3 0f 10 f6 f3 0f 10 f6 f3 0f 10 f6 [0-15] 33 94 85 ?? ?? ?? ?? 88 16 f3 0f 10 d2 f3 0f 10 c0 f3 0f 10 c0 f3 0f 10 ff 46 [0-15] 0f 85 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}