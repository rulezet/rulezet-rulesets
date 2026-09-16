rule PEiD_02193_tElock_0_99_Special_Build____heXer___forgot_ {
  meta:
    description = "[tElock 0.99 Special Build -> heXer & forgot]"
    ep_only     = "false"

  strings:
    $a = { E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05 ?? ?? 00 F5 ?? ?? 00 ED ?? ?? 00 00 00 00 00 00 00 00 00 12 ?? ?? 00 FD ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1D ?? ?? 00 00 00 00 00 30 ?? ?? 00 00 }

  condition:
    $a
}