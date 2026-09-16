rule Trojan_Win32_Bayrob_MX_MTB_2{
	meta:
		description = "Trojan:Win32/Bayrob.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {75 09 53 e8 6e 85 ff ff 59 33 db 57 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}