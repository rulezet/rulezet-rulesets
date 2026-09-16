rule PHP_shell {
	meta:
		description = "Webshells Auto-generated - file shell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "45e8a00567f8a34ab1cccc86b4bc74b9"
	strings:
		$s0 = "AR8iROET6mMnrqTpC6W1Kp/DsTgxNby9H1xhiswfwgoAtED0y6wEXTihoAtICkIX6L1+vTUYWuWz"
		$s11 = "1HLp1qnlCyl5gko8rDlWHqf8/JoPKvGwEm9Q4nVKvEh0b0PKle3zeFiJNyjxOiVepMSpflJkPv5s"
	condition:
		all of them
}