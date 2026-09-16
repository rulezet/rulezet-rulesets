rule compression_algorithm_seen_in_the_game_DreamKiller__32_big_AND_
{
strings:
	$a0 = { ffffff1f[0-20]ffffff3f[0-20]ffffff0f }

condition:
	$a0
}