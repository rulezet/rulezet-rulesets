rule eval_with_comments {
	strings:
		$ = /(^|\s)eval\s*\/\*.{,128}\*\/\s*\(/
	condition: 
        any of them and filesize < 500KB
}