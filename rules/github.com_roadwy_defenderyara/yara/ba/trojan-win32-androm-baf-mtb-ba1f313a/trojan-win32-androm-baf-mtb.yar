rule Trojan_Win32_Androm_BAF_MTB{
	meta:
		description = "Trojan:Win32/Androm.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 45 cc 2b c2 83 c0 04 89 45 ec ff 75 fc b9 21 00 00 00 ff 75 f8 b9 21 00 00 00 ff 75 f0 b9 21 00 00 00 ff 75 f4 b9 21 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}