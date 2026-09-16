rule php_dns {
	meta:
		description = "Laudanum Injector Tools - file dns.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "01d5d16d876c55d77e094ce2b9c237de43b21a16"
		id = "a52e453b-07aa-58b9-91e7-f2426a8e8976"
	strings:
		$s1 = "$query = isset($_POST['query']) ? $_POST['query'] : '';" fullword ascii 
		$s2 = "$result = dns_get_record($query, $types[$type], $authns, $addtl);" fullword ascii 
		$s3 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii 
		$s4 = "foreach (array_keys($types) as $t) {" fullword ascii
	condition:
		filesize < 15KB and all of them
}