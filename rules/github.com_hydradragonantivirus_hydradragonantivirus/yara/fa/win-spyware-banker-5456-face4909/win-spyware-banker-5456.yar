rule Win_Spyware_Banker_5456
{
strings:
	$a0 = { 54a920ffb0d70c21ae335a96f559b316504d0d87688cb16ebc471d5ecc9eacffdcddf4fd285a336a268f74cd77cde8fd342e089afa19c8801b341340fd5180e33d821556b57fcf83b449f9d7558a }


condition:
	$a0
}