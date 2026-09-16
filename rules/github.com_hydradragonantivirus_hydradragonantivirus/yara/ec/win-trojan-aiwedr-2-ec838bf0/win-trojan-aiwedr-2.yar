rule Win_Trojan_Aiwedr_2
{
strings:
	$a0 = { cd21724be822030e0732c0b96d00bf5403fcf3aa8c }


condition:
	$a0
}