rule Trojan_Win32_Redline_GKB_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 ca f6 d1 80 c1 75 32 ca 2a c1 b1 8b 32 c2 2a c8 2a ca 80 f1 0c 02 ca 32 ca 02 ca 32 ca 88 4c 14 18 42 83 fa 0f 72 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}