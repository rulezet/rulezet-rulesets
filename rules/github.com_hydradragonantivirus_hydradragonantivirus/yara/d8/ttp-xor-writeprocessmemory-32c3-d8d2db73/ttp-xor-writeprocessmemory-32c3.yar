rule TTP_XOR_WriteProcessMemory_32c3 {
  strings:
    $key_32c3 = { 65 b1 [2] 57 93 [2] 51 a6 [2] 7f a6 [2] 40 ba }

  condition:
    any of them
}