rule TTP_XOR_WriteProcessMemory_8eff {
  strings:
    $key_8eff = { d9 8d [2] eb af [2] ed 9a [2] c3 9a [2] fc 86 }

  condition:
    any of them
}