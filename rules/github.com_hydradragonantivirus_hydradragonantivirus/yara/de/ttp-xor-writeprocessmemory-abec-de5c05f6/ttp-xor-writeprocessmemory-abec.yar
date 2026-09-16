rule TTP_XOR_WriteProcessMemory_abec {
  strings:
    $key_abec = { fc 9e [2] ce bc [2] c8 89 [2] e6 89 [2] d9 95 }

  condition:
    any of them
}