rule Trojan_BAT_DarkCloud_ABDC_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.ABDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 0b 18 13 04 38 ?? ff ff ff 02 8c ?? 00 00 1b 03 04 6f ?? 00 00 0a 0b 11 05 20 ?? 00 00 00 91 13 04 38 ?? ff ff ff 06 17 58 0a 05 25 5a 05 58 18 5d } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}