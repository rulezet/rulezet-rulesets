rule pos_memory_scrapper_
{
meta:
	author = "@patrickrolsen"
	maltype = "Point of Sale (POS) Malware Memory Scraper"
	version = "0.3"
	description = "POS Memory Scraper"
	date = "01/30/2014"
strings:
	$s1 = "kartoxa" nocase
	$s2 = "CC2 region:"
	$s3 = "CC memregion:"
	$s4 = "target pid:"
	$s5 = "scan all processes:"
	$s6 = "<pid> <PATTERN>"
	$s7 = "KAPTOXA"
	$s8 = "ATTERN"
	$s9 = "\\svhst%p"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}