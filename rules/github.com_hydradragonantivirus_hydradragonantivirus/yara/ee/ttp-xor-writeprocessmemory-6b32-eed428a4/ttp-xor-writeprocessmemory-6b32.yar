rule TTP_XOR_WriteProcessMemory_6b32 {
  strings:
    $key_6b32 = { 3c 40 [2] 0e 62 [2] 08 57 [2] 26 57 [2] 19 4b }

  condition:
    any of them
}