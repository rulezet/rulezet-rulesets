rule TTP_XOR_WriteProcessMemory_4c76 {
  strings:
    $key_4c76 = { 1b 04 [2] 29 26 [2] 2f 13 [2] 01 13 [2] 3e 0f }

  condition:
    any of them
}