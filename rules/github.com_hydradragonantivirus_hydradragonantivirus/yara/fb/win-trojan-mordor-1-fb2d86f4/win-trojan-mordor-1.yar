rule Win_Trojan_Mordor_1
{
strings:
	$a0 = { 1fbf1a01803dba7410b95004bf1a010e1f8135af094747e2f6154cf6b1aef362281b2362282ff3b07cbe89510ada051b001536aec48eb1af4562284634ae03 }


condition:
	$a0
}