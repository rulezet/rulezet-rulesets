rule Trojan_Win32_Ursnif_V_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 02 89 75 d8 8b 75 ec c1 2d 84 f0 49 00 07 8b 75 d8 2d 7e a9 c5 3e 89 4d dc 8d 4d d0 f7 19 8b 4d dc 2b 02 } 		$a_01_1 = {33 55 f4 ff 45 08 8a 4d 08 33 d0 d3 ca 8b 4d ec 89 4d f4 89 16 83 c6 04 4f 75 dc } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}