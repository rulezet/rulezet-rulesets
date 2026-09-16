rule hta_hiding_window 
{
    meta:
    	author = "k3rnelcallz"
        description = "Detects JavaScript hiding browser windows via resizeTo/moveTo"
        sha256 = "2e5934e38666e63c23f5906e5175a1bf5c230972cb57bb8c07dab0630921fa43"
        ref = "malwarebazaar"
		creation_date = "30-11-25"
		last_modified = "30-11-25"
		source = "Malwarebazaar"
		category = "Info"

    strings:
            $a1 = /ActiveXObject/i
        $a2  = /GetObject/i
        $a3   = /ExecQuery/i
        $a4  = /Enumerator/i

                $r = /window\.resizeTo\s*\(/i
        $m = /window\.moveTo\s*\(/i

    condition:
        $r and $m and any of ($a*)
 }