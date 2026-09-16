rule HYTop2006_rar_Folder_2006Z {
	meta:
		description = "Webshells Auto-generated - file 2006Z.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "fd1b6129abd4ab177fed135e3b665488"
	strings:
		$s1 = "wangyong,czy,allen,lcx,Marcos,kEvin1986,myth"
		$s8 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x"
	condition:
		all of them
}