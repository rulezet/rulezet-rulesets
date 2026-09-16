rule Trojan_Win32_Redline_BT_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.BT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d3 e8 89 45 f8 8b 45 d4 01 45 f8 8b 45 f8 33 45 e8 81 45 e0 47 86 c8 61 31 45 fc 2b 5d fc ff 4d d8 89 35 84 bf 44 00 89 5d dc 0f 85 b6 fe ff ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}