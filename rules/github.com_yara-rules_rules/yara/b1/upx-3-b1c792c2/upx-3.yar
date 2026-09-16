import "pe"
rule upx_3 : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="25/02/2013"
		description="UPX 3.X"

	strings:
		$str1={60 BE 00 [2] 00 8D BE 00 [2] FF [1-12] EB 1? 90 90 90 90 90 [1-3] 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01}

	condition:
		$str1 at pe.entry_point
}