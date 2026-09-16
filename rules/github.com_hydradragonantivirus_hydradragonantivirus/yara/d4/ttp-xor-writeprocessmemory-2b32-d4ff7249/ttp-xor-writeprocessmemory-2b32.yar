rule TTP_XOR_WriteProcessMemory_2b32 {
  strings:
    $key_2b32 = { 7c 40 [2] 4e 62 [2] 48 57 [2] 66 57 [2] 59 4b }

  condition:
    any of them
}