rule TTP_XOR_WriteProcessMemory_3e76 {
  strings:
    $key_3e76 = { 69 04 [2] 5b 26 [2] 5d 13 [2] 73 13 [2] 4c 0f }

  condition:
    any of them
}