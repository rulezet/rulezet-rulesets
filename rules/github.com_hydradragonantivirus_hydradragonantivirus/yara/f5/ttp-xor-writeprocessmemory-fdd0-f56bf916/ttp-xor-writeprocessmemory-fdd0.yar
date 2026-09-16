rule TTP_XOR_WriteProcessMemory_fdd0 {
  strings:
    $key_fdd0 = { aa a2 [2] 98 80 [2] 9e b5 [2] b0 b5 [2] 8f a9 }

  condition:
    any of them
}