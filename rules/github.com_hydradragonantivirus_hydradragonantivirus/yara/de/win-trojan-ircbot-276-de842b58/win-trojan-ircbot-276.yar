rule Win_Trojan_IRCBot_276
{
strings:
	$a0 = { 4f657ef38295fdd6b3f192eca27e1f36362e1152bce08ab901947bca9c2e42e6fa7d8cc3dc01e08aa375a5469d9852e4bbff457763c5945bd96b34ee6230aa5b354427506feb5c76bce83c7dd447d3af }


condition:
	$a0
}