rule Win_Spyware_5769_1
{
strings:
	$a0 = { 50dcffff66b9da005ae88ae9ffff53e8d4e7ffff81c40c0300005bc3776d766473662e6178000000ffffffff09000000776d7664 }


condition:
	$a0
}