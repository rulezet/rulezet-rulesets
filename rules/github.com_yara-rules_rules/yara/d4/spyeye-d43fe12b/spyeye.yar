rule spyeye : banker
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "SpyEye X.Y memory"
		date = "2012-05-23" 
		version = "1.0" 
		filetype = "memory"

	strings:
		$spyeye = "SpyEye"
		$a = "%BOTNAME%"
		$b = "globplugins"
		$c = "data_inject"
		$d = "data_before"
		$e = "data_after"
		$f = "data_end"
		$g = "bot_version"
		$h = "bot_guid"
		$i = "TakeBotGuid"
		$j = "TakeGateToCollector"
		$k = "[ERROR] : Omfg! Process is still active? Lets kill that mazafaka!"
		$l = "[ERROR] : Update is not successfull for some reason"
		$m = "[ERROR] : dwErr == %u"
		$n = "GRABBED DATA"
		
	condition:
		$spyeye or (any of ($a,$b,$c,$d,$e,$f,$g,$h,$i,$j,$k,$l,$m,$n))
}