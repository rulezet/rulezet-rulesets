rule Win_Trojan_VECNA832_1
{
strings:
	$a0 = { 40ba8c038b0e8a0383c102cd21b80242992bc9cd21b440b940032bd2cd21b8004233c98b168403 }


condition:
	$a0
}