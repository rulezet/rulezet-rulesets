rule Win_Trojan_Prosiak_4
{
strings:
	$a0 = { 48c64a57e1aa3001da8ff812feff81db6d61696c2e6c75626c696e2e706cef39a26ac2b77ad90192 }


condition:
	$a0
}