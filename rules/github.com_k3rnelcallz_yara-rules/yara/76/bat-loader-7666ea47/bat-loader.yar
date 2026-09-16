rule bat_loader: malicious_png_dropper
{
	meta:
		author = "k3rnelcallz"
		reference = "Malwarebazaar"
		sha = "05527965d2e4af174710298457ba56c449d575aa2937971a6fa785f9a75fdea9"
		description = "Bat loader drops decoded code and executes, cleanup"
		date = "31-12-25"
        tags = "loader, dropper"

	strings:
		$temp_b64 = />>"?%TEMP%\\[A-Za-z0-9_\-]+\.b64"?\s+echo/i

        $ps_convert = "[System.Convert]::FromBase64String"
        $ps_write   = "[System.IO.File]::WriteAllBytes"
        $ps_get_content = "Get-Content -Raw"

        $calls_payload = /call\s+"%TEMP%\\.*\.bat"/ nocase
        $del_payload   = /del\s+"%TEMP%\\.*\.(bat|b64)"/ nocase

    condition:
        $temp_b64 and
        2 of ($ps_convert, $ps_write, $ps_get_content) and
        1 of ($calls_payload, $del_payload)
}