rule Trojan_Win32_Ursnif_AA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {54 6f 77 61 72 64 79 65 61 72 5c 53 68 6f 75 6c 64 6f 6e 5c 73 75 72 65 53 75 6d 6d 65 72 5c 43 72 65 61 74 65 73 69 6e 67 6c 65 5c 61 6c 6c 6f 77 74 6f 42 79 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}