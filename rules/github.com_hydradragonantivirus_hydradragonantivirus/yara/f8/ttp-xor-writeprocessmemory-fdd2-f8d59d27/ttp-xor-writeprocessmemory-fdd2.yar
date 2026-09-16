rule TTP_XOR_WriteProcessMemory_fdd2 {
  strings:
    $key_fdd2 = { aa a0 [2] 98 82 [2] 9e b7 [2] b0 b7 [2] 8f ab }

  condition:
    any of them
}