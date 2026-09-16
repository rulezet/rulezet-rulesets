rule Win_Spyware_Banker_3067
{
strings:
	$a0 = { e8d48e8e4f51677cd871254e620df78d690d80c376824c63ad24f4a128c149d5faab62dfe16ecde201139fef7d1e6ac5d3133c4db47060406fe17d856c52 }


condition:
	$a0
}