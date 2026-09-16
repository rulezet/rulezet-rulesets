rule Trojan_Win32_LummaStealer_FAO_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.FAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c1 89 c8 35 00 01 00 00 21 c8 8a 84 04 ?? ?? ?? ?? 8b 4c ?? 3c 8a 54 0d 00 88 d4 f6 d4 20 c4 f6 d0 20 d0 08 e0 88 44 0d 00 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}