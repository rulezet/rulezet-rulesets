rule Win_Trojan_Agent_35797
{
strings:
	$a0 = { 2bfe13ce8bdf23d80bca33ce13de13da0bde4fe92c010000848480241af80add }


condition:
	$a0
}