rule Trojan_Win32_Azorult_BZ_MTB{
	meta:
		description = "Trojan:Win32/Azorult.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 45 ff 8a 4d fe 24 c0 08 45 fc 8b 45 f8 88 0c 07 8a 4d fd 88 4c 07 01 83 0d } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}