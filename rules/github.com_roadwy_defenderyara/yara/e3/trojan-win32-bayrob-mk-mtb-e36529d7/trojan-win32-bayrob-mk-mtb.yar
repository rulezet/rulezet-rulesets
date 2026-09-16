rule Trojan_Win32_Bayrob_MK_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.MK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d1 c8 89 45 08 8b d0 8a 45 08 c1 ea 08 02 d0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}