rule aspx_shell {
	meta:
		description = "Laudanum Injector Tools - file shell.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "076aa781a004ecb2bf545357fd36dcbafdd68b1a"
		id = "d4287007-79af-59fa-b8c8-3ac08d75b3bd"
	strings:
		$s1 = "remoteIp = HttpContext.Current.Request.Headers[\"X-Forwarded-For\"].Split(new" ascii 
		$s2 = "remoteIp = Request.UserHostAddress;" fullword ascii 
		$s3 = "<form method=\"post\" name=\"shell\">" fullword ascii 
		$s4 = "<body onload=\"document.shell.c.focus()\">" fullword ascii 
	condition:
		filesize < 20KB and all of them
}