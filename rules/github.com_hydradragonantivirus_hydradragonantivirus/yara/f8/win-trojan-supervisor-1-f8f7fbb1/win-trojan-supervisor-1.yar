rule Win_Trojan_Supervisor_1
{
strings:
	$a0 = { 8ed8ba0d04b82825cd212ea11d008ed8ba9d03b82125cd21b434cd21891e19008c061b00 }


condition:
	$a0
}