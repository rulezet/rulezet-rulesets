rule TTP_XOR_WriteProcessMemory_2bd4 {
  strings:
    $key_2bd4 = { 7c a6 [2] 4e 84 [2] 48 b1 [2] 66 b1 [2] 59 ad }

  condition:
    any of them
}