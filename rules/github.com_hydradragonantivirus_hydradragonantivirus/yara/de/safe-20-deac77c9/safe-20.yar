rule _Safe_20_
{
	meta:
		description = "Safe 2.0"
	strings:
		$0 = {83 EC 10 53 56 57 E8 C4 01 00}
	condition:
		$0
}