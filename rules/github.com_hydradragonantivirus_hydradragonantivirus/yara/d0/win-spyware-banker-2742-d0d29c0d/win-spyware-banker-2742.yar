rule Win_Spyware_Banker_2742
{
strings:
	$a0 = { 06dc70d1b30beb629a6035461606a7129c5e1d172f6617c4d4f14ce92ad8eeaace9767282aed6cca9653c293a64a6388dab920283adab344c5473dbcef7f3513d1cef2c9e4b90d9f19e8031b6a58 }


condition:
	$a0
}