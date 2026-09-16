rule Win_Spyware_5449_1
{
strings:
	$a0 = { 575f565683c404d3ce8bf48b3683c404a9bb4e0000e80c000000437c }


condition:
	$a0
}