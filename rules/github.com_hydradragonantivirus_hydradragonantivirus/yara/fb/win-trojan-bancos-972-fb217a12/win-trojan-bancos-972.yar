rule Win_Trojan_Bancos_972
{
strings:
	$a0 = { 39bd1fd355dc57019b62f56c5d84f2d771fca50fc0a524c23b6145c0e373fa4a8ceffd0d192154a9badb376415fa6a75cc8f70e73b2f11c491dab34b2958a80c9225ce2c9300b360d61dab373569 }


condition:
	$a0
}