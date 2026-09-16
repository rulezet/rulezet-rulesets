rule Win_Trojan_Rootkit_30
{
strings:
	$a0 = { f3a674498bb5ecfeffff6a0dbfce0801005933c0f3a674358bb5ecfeffff6a0dbfde0801005933c0f3a67421ff85f8feffff8b85f8feffff0195e8feffff0195f0feffff3b037281e980000000 }


condition:
	$a0
}