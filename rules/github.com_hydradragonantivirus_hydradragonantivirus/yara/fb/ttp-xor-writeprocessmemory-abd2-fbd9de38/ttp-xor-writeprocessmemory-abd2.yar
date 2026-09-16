rule TTP_XOR_WriteProcessMemory_abd2 {
  strings:
    $key_abd2 = { fc a0 [2] ce 82 [2] c8 b7 [2] e6 b7 [2] d9 ab }

  condition:
    any of them
}