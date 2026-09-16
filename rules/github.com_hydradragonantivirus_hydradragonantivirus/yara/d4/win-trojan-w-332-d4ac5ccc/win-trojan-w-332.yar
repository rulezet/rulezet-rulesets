rule Win_Trojan_W_332
{
strings:
	$a0 = { af9b9da2ae0b213b1ddcb8024de46919c61c709a96b27f773b639c9f52d6c669bbaeb0dd920b20fb280222d18892501cc7d7bced11e51b6b5a7bc363e45a2c41 }


condition:
	$a0
}