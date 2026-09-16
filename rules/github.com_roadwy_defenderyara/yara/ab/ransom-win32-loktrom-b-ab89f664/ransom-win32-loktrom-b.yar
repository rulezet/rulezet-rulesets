rule Ransom_Win32_Loktrom_B{
	meta:
		description = "Ransom:Win32/Loktrom.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 03 03 00 00 be ?? ?? 40 00 8d bd c8 f3 ff ff f3 a5 a4 c7 45 f8 ?? 00 00 00 c7 45 f0 00 00 00 00 e8 14 01 00 00 89 45 f4 c7 45 f0 00 00 00 00 eb 09 8b 4d f0 83 c1 01 89 4d f0 8b 55 f0 3b 55 f4 0f 8d d0 00 00 00 8b 45 f0 8a 8c 05 c8 f3 ff ff 88 4d fe 8b 55 f0 83 c2 01 89 55 dc 0f be 45 fe 8b 4d dc 33 4d f8 03 c1 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}