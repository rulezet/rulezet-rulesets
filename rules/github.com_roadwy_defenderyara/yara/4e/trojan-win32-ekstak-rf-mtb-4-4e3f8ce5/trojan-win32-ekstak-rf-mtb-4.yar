rule Trojan_Win32_Ekstak_RF_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {a1 c8 2c 47 00 8b 4d 14 8b 15 a4 5e 48 00 50 51 52 6a 00 ff 15 ?? f5 46 00 e9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}