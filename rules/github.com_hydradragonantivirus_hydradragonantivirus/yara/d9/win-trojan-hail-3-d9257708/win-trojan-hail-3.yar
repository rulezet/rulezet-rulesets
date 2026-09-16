rule Win_Trojan_Hail_3
{
strings:
	$a0 = { b8e6038d966f0091cd21b9004233c08bd091cd21b90040b81d00918d96fe02cd21b901572e }


condition:
	$a0
}