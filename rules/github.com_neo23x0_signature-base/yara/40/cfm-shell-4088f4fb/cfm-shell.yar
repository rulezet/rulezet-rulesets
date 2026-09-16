rule cfm_shell {
	meta:
		description = "Laudanum Injector Tools - file shell.cfm"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "885e1783b07c73e7d47d3283be303c9719419b92"
		id = "5308eecf-a59f-5100-ab60-5034c5b73e7e"
	strings:
		$s1 = "Executable: <Input type=\"text\" name=\"cmd\" value=\"cmd.exe\"><br>" fullword ascii 
		$s2 = "<cfif ( #suppliedCode# neq secretCode )>" fullword ascii 
		$s3 = "<cfif IsDefined(\"form.cmd\")>" fullword ascii
	condition:
		filesize < 20KB and 2 of them
}