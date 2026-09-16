rule Win_Trojan_ATII_2
{
strings:
	$a0 = { 0e560eb02e508ec033ffb178f3a46a12cb56be84008ed939047407a58944fe8704ab5e07061fad915f57f3a4cb601e0680f44b753eb8023dcdd6723793b58c }


condition:
	$a0
}