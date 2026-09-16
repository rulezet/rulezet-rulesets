rule Win_Trojan_Hupigon_690
{
strings:
	$a0 = { 7ea6eb5a8116c614c479848afa30cd89ef05f465339bb6246bc1e0ec5e91c40ef17ea95cf62be16fac74aa296a698338fcf17ac0b0a603653878ba25fdd090a6b9 }


condition:
	$a0
}