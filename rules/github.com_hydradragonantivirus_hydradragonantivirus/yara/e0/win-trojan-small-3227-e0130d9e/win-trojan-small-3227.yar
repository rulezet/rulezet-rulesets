rule Win_Trojan_Small_3227
{
strings:
	$a0 = { 9573d99929d2f3895defa87c72168dd8894e86bce95ab5a0495aada0518ba67ce9d19b3c774e8de572268de0dc7df6c80dd6f5d00deab9ce4f7dd37c53d2d2c053d212e6e95eada0613c69cc53d26791cde2 }


condition:
	$a0
}