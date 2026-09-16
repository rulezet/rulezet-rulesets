rule Win_Spyware_Banker_3416
{
strings:
	$a0 = { 9fc5d5c8f84ae1dbf4cc07e31c139b9ea0461739adb80cc0cb4b3c26e2130211f4b7d795e42e2259e08dd00d0f584cdd26e866464f7f6e8f26490a9fddad381dcfc828c3773ce0b899b6b7 }


condition:
	$a0
}