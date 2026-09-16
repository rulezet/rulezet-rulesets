rule Win_Trojan_Natas_18
{
strings:
	$a0 = { f819ed81f55c1429f6bf8ec787c181c613b8f9f519c081c050f22d08e92bc9fd87df81c9fdb587d74881edfeffd1c1d38a773785c07fef }


condition:
	$a0
}