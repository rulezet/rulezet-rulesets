rule TTP_XOR_WriteProcessMemory_3e56 {
  strings:
    $key_3e56 = { 69 24 [2] 5b 06 [2] 5d 33 [2] 73 33 [2] 4c 2f }

  condition:
    any of them
}