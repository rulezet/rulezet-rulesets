rule TTP_XOR_WriteProcessMemory_ab17 {
  strings:
    $key_ab17 = { fc 65 [2] ce 47 [2] c8 72 [2] e6 72 [2] d9 6e }

  condition:
    any of them
}