rule Trojan_Win32_Bayrob_MX_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 ca 39 d0 7d 0c 81 05 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}