rule Win_Trojan_RanDir_3
{
strings:
	$a0 = { 465d042e636f6d042e6578655589e581ec0402b80800509a8d0d6300408846febf20010e57bf }


condition:
	$a0
}