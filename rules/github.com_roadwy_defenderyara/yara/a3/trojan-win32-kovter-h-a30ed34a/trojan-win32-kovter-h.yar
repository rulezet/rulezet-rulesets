rule Trojan_Win32_Kovter_H{
	meta:
		description = "Trojan:Win32/Kovter.H,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f8 8a 54 32 ff 80 e2 0f 32 c2 88 45 f3 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 1a ff 80 e2 f0 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}