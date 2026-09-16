rule CN_Honker_Webshell_PHP_php1 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php1.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "c2f4b150f53c78777928921b3a985ec678bfae32"
		id = "5fe78cc6-8be3-595f-a082-e361259938e5"
	strings:
		$s7 = "$sendbuf = \"site exec \".$_POST[\"SUCommand\"].\"\\r\\n\";" fullword ascii 
		$s8 = "elseif(function_exists('passthru')){@ob_start();@passthru($cmd);$res = @ob_get_c" ascii 
		$s18 = "echo Exec_Run($perlpath.' /tmp/spider_bc '.$_POST['yourip'].' '.$_POST['yourport" ascii 
	condition:
		filesize < 621KB and all of them
}