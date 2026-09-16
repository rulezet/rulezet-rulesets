import "pe"
rule Solidshield_Protector_V1_X____Solidshield_Technologies_____Sign_By_fly {
  strings:
    $a0 = { 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 00 60 89 00 0A 00 00 00 46 33 00 00 00 00 00 00 00 00 }

  condition:
    $a0 at pe.entry_point
}