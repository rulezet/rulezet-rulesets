import "pe"
rule _Comt_010_duckling_
{
	meta:
		description = "Comt 0.10 (duckling)"
	strings:
		$0 = {2D 64 55 43 4B 2D 00 2E 42 00 00 3D 0D 0A 25 30 30 25 40 40 50 5A 2D 72 6D 2D 72 6D 2D 4C 23 50 5F 52 5E 4E 31 35 52 58 2D 71 6E 2D 71 6E 50 2D 40 21 50 59 2D 21 70 2D 21 60 2D 21 30 50 5D 3D 0D 0A 58 2D 62 21 50 5F 57 52 5E 21 35 47 47 21}
	condition:
		$0 at pe.entry_point
}