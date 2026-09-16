rule Win_Trojan_Sterculius_9
{
strings:
	$a0 = { 5a7437807c03537431b8024233c999e8a6ff2d030095b440b9f000bae001e897ffb8004233 }


condition:
	$a0
}