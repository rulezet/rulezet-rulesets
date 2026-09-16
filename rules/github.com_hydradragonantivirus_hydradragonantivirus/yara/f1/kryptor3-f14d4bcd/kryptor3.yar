rule kryptor3
{
	meta:
		author = "PEiD"
		description = "k.kryptor 3 -> r!sc"
		group = "128"
		function = "0"
	strings:
		$a0 = { EB 66 87 DB }
	condition:
		$a0
}