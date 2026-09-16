rule Trojan_Win64_Tedy_NTD_MTB{
	meta:
		description = "Trojan:Win64/Tedy.NTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 c3 48 03 c0 49 83 24 c4 00 33 c0 eb db 48 89 5c 24 ?? 48 89 6c 24 ?? 48 89 74 24 ?? 57 48 83 ec 20 bf ?? ?? ?? ?? 48 8d 1d 60 f5 0a } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}