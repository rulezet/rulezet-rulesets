rule Win_Trojan_Killer_5
{
strings:
	$a0 = { c87475eabde5fbebddbd6c439fd4e44d0f85166456759203b5e4becdef011b0eeacdb557443ec086727e78a7cf8d75e4f29c8201d0c780cee460dbc1 }


condition:
	$a0
}