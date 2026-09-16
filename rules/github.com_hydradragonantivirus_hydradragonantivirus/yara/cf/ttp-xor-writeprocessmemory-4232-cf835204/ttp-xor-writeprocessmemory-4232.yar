rule TTP_XOR_WriteProcessMemory_4232 {
  strings:
    $key_4232 = { 15 40 [2] 27 62 [2] 21 57 [2] 0f 57 [2] 30 4b }

  condition:
    any of them
}