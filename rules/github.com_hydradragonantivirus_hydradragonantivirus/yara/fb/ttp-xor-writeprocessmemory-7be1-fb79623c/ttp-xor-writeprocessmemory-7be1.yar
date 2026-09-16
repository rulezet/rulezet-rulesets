rule TTP_XOR_WriteProcessMemory_7be1 {
  strings:
    $key_7be1 = { 2c 93 [2] 1e b1 [2] 18 84 [2] 36 84 [2] 09 98 }

  condition:
    any of them
}