rule PickleFile {
	meta:
		author = "Eoin Wickens - Eoin@HiddenLayer.com"
		description = "Detects Pickle files"
		date = "2022-09-16"
	strings:
		$header_cos = "cos"
		$header_runpy = "runpy"
		$header_builtins = "builtins"
		$header_ccommands = "ccommands"
		$header_subprocess = "subprocess"
		$header_cposix = "cposix\nsystem"
		$header_c_builtin = "c__builtin__"
		$header_pickle_proto_1 = {80 01}
		$header_pickle_proto_2 = {80 02}
		$header_pickle_proto_3 = {80 03}
		$header_pickle_proto_4 = {80 04}
		$header_pickle_proto_5 = {80 05}
	condition:
		(
			for any of them: ($ at 0) or $header_runpy at 1 or
			$header_subprocess at 1
		)

}