rule Win_Trojan_Bancos_1301
{
strings:
	$a0 = { f159b1edf780883105e31fe6b70101b91872bdc8b896cbd2f05c7bb8ccfff7f96d950741e22283ef337746429e27ed4e92ab11aea1d3ed1cf02eafc10cc8546f5aea721ee060a3ca6dfffcc2332fe171536adb62 }


condition:
	$a0
}