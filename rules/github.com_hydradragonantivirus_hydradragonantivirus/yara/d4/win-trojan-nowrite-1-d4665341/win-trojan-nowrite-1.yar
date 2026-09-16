rule Win_Trojan_Nowrite_1
{
strings:
	$a0 = { 80fc04733680fc027231525051b404cd1a595880fa31750380e4fe5a0aed751b0af6741cf6c280 }


condition:
	$a0
}