rule Win_Trojan__0654_0001_000_1
{
strings:
	$a0 = { 886e00cd21b440b95b015b5a525383c2fccd215bb43ecd21eb0e5bb43ecd21b44fcd217203e9f6 }


condition:
	$a0
}