rule Win_Trojan_EvenBeeper_2
{
strings:
	$a0 = { da4733dbe3fe600950a920770347 }


condition:
	$a0
}