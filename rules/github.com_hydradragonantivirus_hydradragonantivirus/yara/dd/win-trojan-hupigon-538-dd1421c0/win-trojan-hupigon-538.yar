rule Win_Trojan_Hupigon_538
{
strings:
	$a0 = { 37e274d0f5cb0bdf1aeb414217a844a666da3ccd4c833403dfeff1364c6d6d406f2702a15157916a29282057b70c5544be30667d83e73332feb3a39210c2ba8fd087a9f074fbbd9b6bac8feea168 }


condition:
	$a0
}