rule Trojan_Win64_LeakyStealer_YBE_MTB{
	meta:
		description = "Trojan:Win64/LeakyStealer.YBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 2b 41 30 03 49 ff c3 49 8b 82 80 00 00 00 48 ff c0 83 e0 3f 49 89 82 } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}