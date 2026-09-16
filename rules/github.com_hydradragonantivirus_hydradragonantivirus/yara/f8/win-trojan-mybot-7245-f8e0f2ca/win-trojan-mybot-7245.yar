rule Win_Trojan_Mybot_7245
{
strings:
	$a0 = { ad39c31f37fb849b217c1d48e1e16c12dcfb85fd47988b681dcaf0b4ac22abf8c2ccf450f60c8c1bab54cbbfbadb640ec05e31b4dcddbf325d20669f0acf3aaa9701edc3c5b9fff3a9dc67c54d5c }


condition:
	$a0
}