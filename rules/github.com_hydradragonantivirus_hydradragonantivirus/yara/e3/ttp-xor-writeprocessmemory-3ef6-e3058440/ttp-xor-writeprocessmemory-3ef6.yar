rule TTP_XOR_WriteProcessMemory_3ef6 {
  strings:
    $key_3ef6 = { 69 84 [2] 5b a6 [2] 5d 93 [2] 73 93 [2] 4c 8f }

  condition:
    any of them
}