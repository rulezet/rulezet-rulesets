rule TTP_XOR_WriteProcessMemory_5be1 {
  strings:
    $key_5be1 = { 0c 93 [2] 3e b1 [2] 38 84 [2] 16 84 [2] 29 98 }

  condition:
    any of them
}