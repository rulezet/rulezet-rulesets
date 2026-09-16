rule TTP_XOR_WriteProcessMemory_6c32 {
  strings:
    $key_6c32 = { 3b 40 [2] 09 62 [2] 0f 57 [2] 21 57 [2] 1e 4b }

  condition:
    any of them
}