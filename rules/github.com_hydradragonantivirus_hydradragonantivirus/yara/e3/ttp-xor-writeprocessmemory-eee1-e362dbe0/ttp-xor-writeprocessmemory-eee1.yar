rule TTP_XOR_WriteProcessMemory_eee1 {
  strings:
    $key_eee1 = { b9 93 [2] 8b b1 [2] 8d 84 [2] a3 84 [2] 9c 98 }

  condition:
    any of them
}