rule Trojan_BAT_AsyncRAT_AMMB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 17 59 91 07 08 07 8e 69 5d 1f ?? 58 1b 58 1f 39 59 17 59 91 61 03 08 20 ?? ?? ?? ?? 58 20 ?? ?? ?? ?? 59 03 8e 69 5d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}