rule Anubis_RC__32_lil_76_
{
strings:
	$a0 = { 71e6d3a7794dacd0fc91c93abd54471efb7aa58cd4ddb863bec5b3e5a20c88a9da29df394ccba82b24aa224bf9a6704136b0e25aff33e47d8b082060787fab5ed2572c7c0d7e6ddc28c39453 }

condition:
	$a0
}