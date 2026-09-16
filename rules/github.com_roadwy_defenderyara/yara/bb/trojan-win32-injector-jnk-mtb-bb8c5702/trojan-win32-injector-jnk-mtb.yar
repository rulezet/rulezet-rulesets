rule Trojan_Win32_Injector_JNK_MTB{
	meta:
		description = "Trojan:Win32/Injector.JNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 00 08 04 40 0b 98 0d bf 04 c2 01 11 0a 00 ff 03 26 00 00 00 0f } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}