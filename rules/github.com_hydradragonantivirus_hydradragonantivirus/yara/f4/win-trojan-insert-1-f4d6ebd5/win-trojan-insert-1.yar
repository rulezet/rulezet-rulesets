rule Win_Trojan_Insert_1
{
strings:
	$a0 = { 40817d294f4d75398b4515990b451775308bfb8ec642ae74019981fa1a017304e2f3eb1d0e1f96b0e9268607a279002b }


condition:
	$a0
}