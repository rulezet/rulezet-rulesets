rule Win_Trojan_Agent_33559
{
strings:
	$a0 = { c0298c77bf1ce749c3b9efbf1aa907e32c91a312eaf50cc09762878cc718db93d4bd960b2c7a388cb3c7fba6a4cec3a082f3d8f01f7799c7b1289d0dd39aa0e7595a904f5e6f260be2b9d3a8ee9b14eba460 }


condition:
	$a0
}