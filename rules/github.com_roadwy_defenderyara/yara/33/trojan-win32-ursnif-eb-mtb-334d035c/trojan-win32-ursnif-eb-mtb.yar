rule Trojan_Win32_Ursnif_EB_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 c0 0f b6 4d e7 c1 e9 04 0f b6 d0 83 e2 0f 33 ca c1 e8 04 33 04 8b 89 45 c0 eb c5 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}