rule Win_Trojan_UCF_1
{
strings:
	$a0 = { 2acd2181f9c907721a80fe00721580fa017210b85f03bb2010b90100ba8000cd13ebf0 }


condition:
	$a0
}