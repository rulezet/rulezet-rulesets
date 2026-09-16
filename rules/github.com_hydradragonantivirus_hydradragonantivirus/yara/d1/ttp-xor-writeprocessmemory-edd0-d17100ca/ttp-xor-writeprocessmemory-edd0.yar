rule TTP_XOR_WriteProcessMemory_edd0 {
  strings:
    $key_edd0 = { ba a2 [2] 88 80 [2] 8e b5 [2] a0 b5 [2] 9f a9 }

  condition:
    any of them
}