rule WEB_INF_web {
	meta:
		description = "Laudanum Injector Tools - file web.xml"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "0251baed0a16c451f9d67dddce04a45dc26cb4a3"
		id = "8d0a008c-56d1-59ef-8521-0697add21ba9"
	strings:
		$s1 = "<servlet-name>Command</servlet-name>" fullword ascii 
		$s2 = "<jsp-file>/cmd.jsp</jsp-file>" fullword ascii
	condition:
		filesize < 1KB and all of them
}