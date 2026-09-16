rule Win_Trojan_Ranger_1
{
strings:
	$a0 = { 03dd89075bb440b922018bd5cd21b8004233c98bd1cd21b440b90900ba0d0103d5cd21b43e }


condition:
	$a0
}