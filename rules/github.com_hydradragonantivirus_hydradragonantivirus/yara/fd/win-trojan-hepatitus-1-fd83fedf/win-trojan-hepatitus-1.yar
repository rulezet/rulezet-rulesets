rule Win_Trojan_Hepatitus_1
{
strings:
	$a0 = { b8ad0150b8ad0450e830195959c60699044dc6069a045ac6069b04b6c6069c0400c6069d041a }


condition:
	$a0
}