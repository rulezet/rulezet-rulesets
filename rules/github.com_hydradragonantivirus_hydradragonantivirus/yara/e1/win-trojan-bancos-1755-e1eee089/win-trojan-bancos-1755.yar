rule Win_Trojan_Bancos_1755
{
strings:
	$a0 = { 440cb7a67374648af72440576b3b5c0161143adc7ff7f58e3f8f438b36a09bb2f2f1de55caee38d439a9d0687ff0c36008d0d79d3a91c54f9dc0cb865f502bb1fce77ba9f43b }


condition:
	$a0
}