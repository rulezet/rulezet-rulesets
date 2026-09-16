rule obfuscated_eval {
    strings: 
	$ = /\\x65\s*\\x76\s*\\x61\s*\\x6C/
	$ = "\"/.*/e\""
    condition: any of them
}