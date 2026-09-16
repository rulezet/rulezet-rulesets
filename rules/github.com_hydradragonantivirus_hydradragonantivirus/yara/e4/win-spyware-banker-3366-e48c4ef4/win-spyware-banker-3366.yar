rule Win_Spyware_Banker_3366
{
strings:
	$a0 = { 4e313af755d49cc26405378623e255fa6180f0fd954ad6b822c924f6e3cb4ba6620707c51537da8b37a5e66b05e8aa3ee4df88413e64904ebd5de8734eef2fb199853d681ebf }


condition:
	$a0
}