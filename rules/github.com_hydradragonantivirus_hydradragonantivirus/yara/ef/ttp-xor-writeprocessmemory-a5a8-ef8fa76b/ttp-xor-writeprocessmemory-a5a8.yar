rule TTP_XOR_WriteProcessMemory_a5a8 {
  strings:
    $key_a5a8 = { f2 da [2] c0 f8 [2] c6 cd [2] e8 cd [2] d7 d1 }

  condition:
    any of them
}