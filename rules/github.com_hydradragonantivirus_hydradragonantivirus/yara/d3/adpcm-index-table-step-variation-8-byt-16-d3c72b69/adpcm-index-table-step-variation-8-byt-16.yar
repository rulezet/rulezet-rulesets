rule ADPCM_index_table__step_variation___8_byt_16_
{
strings:
	$a0 = { FFFFFFFF02040608FFFFFFFF02040608 }

condition:
	$a0
}