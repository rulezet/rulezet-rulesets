rule Win_Trojan_Bancos_711
{
strings:
	$a0 = { ce8d11ac93f23638ea686ed7dee178854a06f79ad6f7d0ed4f9ab74a03ef09f564c1319de40fbbaa439393ec336098c8a94c9487e8ba777abf7a6ef4ec6fdc0d28 }


condition:
	$a0
}