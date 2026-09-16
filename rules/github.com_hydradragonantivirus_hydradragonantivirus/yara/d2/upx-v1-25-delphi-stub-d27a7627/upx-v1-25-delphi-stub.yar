import "pe"
rule UPX_v1_25__Delphi__Stub
{
strings:
		$a0 = { 60 BE 00 ?? ?? 00 8D BE 00 ?? ?? FF  }

condition:
		$a0 at pe.entry_point
}