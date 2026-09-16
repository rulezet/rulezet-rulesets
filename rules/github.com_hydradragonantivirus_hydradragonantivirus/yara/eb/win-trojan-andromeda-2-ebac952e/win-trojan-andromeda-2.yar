rule Win_Trojan_Andromeda_2
{
strings:
	$a0 = { 2e8a0432c42e8804463bf175f3c3b42ccd2102c402 }


condition:
	$a0
}