rule TTP_XOR_WriteProcessMemory_3976 {
  strings:
    $key_3976 = { 6e 04 [2] 5c 26 [2] 5a 13 [2] 74 13 [2] 4b 0f }

  condition:
    any of them
}