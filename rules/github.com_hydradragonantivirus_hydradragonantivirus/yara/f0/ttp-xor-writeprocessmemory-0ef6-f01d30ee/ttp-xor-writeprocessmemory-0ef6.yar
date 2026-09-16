rule TTP_XOR_WriteProcessMemory_0ef6 {
  strings:
    $key_0ef6 = { 59 84 [2] 6b a6 [2] 6d 93 [2] 43 93 [2] 7c 8f }

  condition:
    any of them
}