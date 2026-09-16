rule Trojan_Win32_Ursnif_BC_MTB_3{
	meta:
		description = "Trojan:Win32/Ursnif.BC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2e 65 78 65 00 40 47 65 74 46 69 72 73 74 56 69 63 65 43 69 74 79 40 34 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}