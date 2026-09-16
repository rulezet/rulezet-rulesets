rule StarForce_V1_X_V3_X____StarForce_Copy_Protection_System
{
strings:
		$a0 = { 68 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}