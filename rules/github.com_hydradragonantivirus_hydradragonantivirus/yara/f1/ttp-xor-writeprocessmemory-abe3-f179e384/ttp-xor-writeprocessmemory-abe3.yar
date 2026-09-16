rule TTP_XOR_WriteProcessMemory_abe3 {
  strings:
    $key_abe3 = { fc 91 [2] ce b3 [2] c8 86 [2] e6 86 [2] d9 9a }

  condition:
    any of them
}