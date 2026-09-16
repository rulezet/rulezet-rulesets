rule Win_Trojan_Aztec_1
{
strings:
	$a0 = { 33c004ff480bc075fb7401f4609ce8000000008b[0-10]8bc581ed13104000 }


condition:
	$a0
}