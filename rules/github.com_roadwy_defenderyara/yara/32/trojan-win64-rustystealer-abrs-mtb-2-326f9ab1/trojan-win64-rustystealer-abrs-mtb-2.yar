rule Trojan_Win64_RustyStealer_ABRS_MTB_2{
	meta:
		description = "Trojan:Win64/RustyStealer.ABRS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 39 f9 89 c8 ?? ?? 31 d2 f7 ?? 8d 42 01 8a 04 [0-02] 30 04 0c 48 ff c1 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}