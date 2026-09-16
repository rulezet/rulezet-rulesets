rule Trojan_BAT_Avemariarat_VN_MTB{
	meta:
		description = "Trojan:BAT/Avemariarat.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 07 61 08 11 ?? 91 61 b4 9c 1f ?? 2b ?? 90 09 06 00 09 11 ?? 02 11 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}