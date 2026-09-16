import "pe"
rule _DBPE_v210_
{
	meta:
		description = "DBPE v2.10"
	strings:
		$0 = {EB 20 9C 55 57 56 52 51 53 9C E8 5D 81 ED EB 58 75 73 65 72 33 32 2E}
		$1 = {EB 20 40 9C 55 57 56 52 51 53 9C E8 5D 81 ED 9C 6A 10 73 0B EB 02 C1 51}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}