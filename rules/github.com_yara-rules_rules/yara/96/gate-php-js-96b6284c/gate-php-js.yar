rule gate_php_js {
    
    strings: 
		$ = /\/gate.php\?token=.{,10}&host=/
    condition: any of them
}