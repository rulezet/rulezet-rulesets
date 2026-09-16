rule Win_Trojan_Dina_1
{
strings:
	$a0 = { 4e0026a37a0326c7064c003b0026c7064e002400cb80fc02740880fc037403cddecfcdde72fb }


condition:
	$a0
}