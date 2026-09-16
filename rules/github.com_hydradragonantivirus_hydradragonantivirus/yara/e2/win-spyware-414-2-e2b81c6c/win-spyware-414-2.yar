rule Win_Spyware_414_2
{
strings:
	$a0 = { 5f512e54d8901b7a9788c5efa53a5e5e866ea8e79d9fd436c72f3c94adb5ea0f231cd548d78a9ddac4c95b91454020bc6bf1dd1ae2e0a8a82441362e93a53037e08dc37a14bf7ef140ef8053df5e }


condition:
	$a0
}