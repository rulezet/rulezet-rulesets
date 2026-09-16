rule Win_Trojan_Sauron_4
{
strings:
	$a0 = { 81ed030152c317071fbf050103fdbe00018b450189048b450389440233c98bf18bf98bd18bd98be9b80001519d }


condition:
	$a0
}