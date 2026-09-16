rule Trojan_Win32_Fareit_VM_MTB{
	meta:
		description = "Trojan:Win32/Fareit.VM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 10 0f b6 14 3a 33 c2 3d ?? ?? ?? ?? 76 } 		$a_01_1 = {8b 55 10 88 04 3a } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}