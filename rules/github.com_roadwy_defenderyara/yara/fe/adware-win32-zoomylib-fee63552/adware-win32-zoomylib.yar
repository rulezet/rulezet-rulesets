rule Adware_Win32_ZoomyLib{
	meta:
		description = "Adware:Win32/ZoomyLib,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 6e 73 74 61 6c 6c 65 72 55 74 69 6c 73 2e 64 6c 6c 00 43 49 00 43 4e 47 00 48 52 4e 00 4b 42 73 00 52 53 00 57 41 4d 00 67 43 55 44 00 67 49 44 00 69 43 50 4f 00 6f 49 53 00 72 4f 41 00 72 56 46 00 73 49 44 46 00 75 44 47 00 75 50 56 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}