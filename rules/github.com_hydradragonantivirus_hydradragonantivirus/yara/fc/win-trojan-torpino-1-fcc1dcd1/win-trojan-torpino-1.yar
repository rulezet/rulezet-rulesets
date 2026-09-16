rule Win_Trojan_Torpino_1
{
strings:
	$a0 = { b1ae9471ba5028988d81847b89f3676c86daa17f977eb8ba5a803551415a8852ba48dd49b7a40ba4 }


condition:
	$a0
}