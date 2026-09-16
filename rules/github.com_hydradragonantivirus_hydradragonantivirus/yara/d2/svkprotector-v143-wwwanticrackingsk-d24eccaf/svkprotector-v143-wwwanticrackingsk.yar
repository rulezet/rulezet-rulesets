import "pe"
rule _SVKProtector_v143__wwwanticrackingsk_
{
	meta:
		description = "SVK-Protector v1.43 -> www.anticracking.sk"
	strings:
		$0 = {78 4E 88 4C 0E B0 3C 78 4E 97 56 7B 94 90 00 00 08 DB 5C 50 20 00 05}
	condition:
		$0 at pe.entry_point
}