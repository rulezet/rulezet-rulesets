rule Win_Trojan_SillyWilly_1
{
strings:
	$a0 = { 8b1ab9d00881e97300bf730003fd311d47e2fb }


condition:
	$a0
}