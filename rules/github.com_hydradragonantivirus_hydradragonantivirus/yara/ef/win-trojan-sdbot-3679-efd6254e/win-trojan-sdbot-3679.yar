rule Win_Trojan_SdBot_3679
{
strings:
	$a0 = { a31270150c47b7d476c77718c03d0bbe58fecb61c6de72784f92789bce3c4fe207255fa9b1b87d39d96f7a45b2bd2a7582dac179bb15cec7faa2faf22c17c8cf1b1cf165cfc1feaf0a7c146fe6aa }


condition:
	$a0
}