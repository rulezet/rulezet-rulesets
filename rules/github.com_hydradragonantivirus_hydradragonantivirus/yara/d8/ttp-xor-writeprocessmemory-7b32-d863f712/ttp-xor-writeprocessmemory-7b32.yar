rule TTP_XOR_WriteProcessMemory_7b32 {
  strings:
    $key_7b32 = { 2c 40 [2] 1e 62 [2] 18 57 [2] 36 57 [2] 09 4b }

  condition:
    any of them
}