rule Win_Trojan_Trivial_316
{
strings:
	$a0 = { 2000ba3201cd21b42fcd21b43db0028bd381c21e00cd218bd8b440b93800ba0001cd21b43ecd21b44fcd2173da }


condition:
	$a0
}