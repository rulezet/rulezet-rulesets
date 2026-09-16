rule Win_Trojan_Autorun_500
{
strings:
	$a0 = { 5b6175746f72756e0d0a2ceaebd7d4d1c0cae4ebe0eaf7e4ee9cccd4ebf1ea646b4c4153444b }


condition:
	$a0
}