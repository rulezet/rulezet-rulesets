rule Trojan_Win32_Redline_GCX_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 c2 d1 d0 ca 80 c2 ad c0 c2 05 80 c2 5e 80 f2 7b 80 c2 3b 80 f2 44 00 ca 88 c5 30 d5 80 c5 67 88 6c 04 30 83 f8 2d 74 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}