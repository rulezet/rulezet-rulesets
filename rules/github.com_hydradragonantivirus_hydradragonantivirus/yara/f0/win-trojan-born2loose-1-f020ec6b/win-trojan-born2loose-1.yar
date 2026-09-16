rule Win_Trojan_Born2Loose_1
{
strings:
	$a0 = { 4775253fff8bc8fec1b2808a777980e603d1e88bd8b4032407e80600597302e2ddc3facd13c356 }


condition:
	$a0
}