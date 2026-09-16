rule Win_Trojan__1839_0016_000_1
{
strings:
	$a0 = { 075a595b58eb01902eff2ebc059c2eff1ebc05c32e8b1eec052e8b0ef4052e8b16f205b80157e8 }


condition:
	$a0
}