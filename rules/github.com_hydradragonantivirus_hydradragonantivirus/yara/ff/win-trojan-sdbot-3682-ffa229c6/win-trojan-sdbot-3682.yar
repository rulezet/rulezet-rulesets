rule Win_Trojan_SdBot_3682
{
strings:
	$a0 = { 8c58bef6cc3c1919579b587fbb0f2974f34f12f5f4a2335bb0291f35cbeb4cdb067793fbe5badbf752daf634502e074d0537ef4157ede139f1ea9bb72cdb0cc65d6381c6eb2d979198bcb197bf09 }


condition:
	$a0
}