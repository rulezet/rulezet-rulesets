rule Win_Trojan_Hupigon_691
{
strings:
	$a0 = { 282de631fdab737c5f4092e32df886270828f8bf019ddb1835e6925669cce409d9c99945c2c8e08b6cf11260a18df4cb305266237dbc552bfeda688a520e783d01 }


condition:
	$a0
}