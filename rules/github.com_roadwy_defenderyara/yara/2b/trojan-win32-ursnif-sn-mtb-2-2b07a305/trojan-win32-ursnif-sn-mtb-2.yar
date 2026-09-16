rule Trojan_Win32_Ursnif_SN_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.SN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 0f b7 08 8b 45 f8 8b 40 1c 8d 04 88 8b 04 18 03 c3 ff d0 5f 5e 33 c0 5b 8b e5 5d c3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}