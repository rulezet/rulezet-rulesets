rule Win_Trojan_Agent_33603
{
strings:
	$a0 = { 251c2fb3f11e6a8f39fdbab46a7a0632e2d9beeafe0f98c70271b8768c6adf6a2aa6d1fdfaa11369602b953a9f57ef590273e44ea695742193581ee1218a0bb9de6d82e32e1550d5ee94e6c88fc2cc4a48e5 }


condition:
	$a0
}