rule Trojan_Win32_Ursnif_MK_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 c0 48 29 c3 81 fb ?? ?? ?? ?? 75 f3 } 		$a_03_1 = {ac 30 d0 aa c1 ca ?? e2 f7 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}