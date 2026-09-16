rule Win_Adware_Lop_201
{
strings:
	$a0 = { b6281a73de4f7cf556cd90c44538245f88ace42c7fe632d021c0b433114ef9c35a88554f797601ec2bb60e67fe6dd77771d23367fb7c0c9b4ab18b1a }


condition:
	$a0
}