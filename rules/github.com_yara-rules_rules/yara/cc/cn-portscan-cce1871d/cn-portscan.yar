rule CN_Portscan : APT
{
    meta:
        description = "CN Port Scanner"
        author = "Florian Roth"
        release_date = "2013-11-29"
        confidential = false
		score = 70
    strings:
    	$s1 = "MZ"
		$s2 = "TCP 12.12.12.12"
    condition:
        ($s1 at 0) and $s2
}