rule TTP_XOR_WriteProcessMemory_abb1 {
  strings:
    $key_abb1 = { fc c3 [2] ce e1 [2] c8 d4 [2] e6 d4 [2] d9 c8 }

  condition:
    any of them
}