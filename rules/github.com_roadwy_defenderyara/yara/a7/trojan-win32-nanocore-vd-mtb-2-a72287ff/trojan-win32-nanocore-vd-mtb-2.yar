rule Trojan_Win32_NanoCore_VD_MTB_2{
	meta:
		description = "Trojan:Win32/NanoCore.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 d2 81 c2 ?? ?? ?? ?? 80 34 01 ?? 41 39 d1 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}