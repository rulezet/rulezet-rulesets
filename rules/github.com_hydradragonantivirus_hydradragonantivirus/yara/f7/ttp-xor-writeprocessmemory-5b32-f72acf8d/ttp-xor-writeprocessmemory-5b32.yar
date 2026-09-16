rule TTP_XOR_WriteProcessMemory_5b32 {
  strings:
    $key_5b32 = { 0c 40 [2] 3e 62 [2] 38 57 [2] 16 57 [2] 29 4b }

  condition:
    any of them
}