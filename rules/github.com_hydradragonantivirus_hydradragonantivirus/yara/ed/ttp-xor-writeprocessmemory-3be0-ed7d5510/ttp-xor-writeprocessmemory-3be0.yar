rule TTP_XOR_WriteProcessMemory_3be0 {
  strings:
    $key_3be0 = { 6c 92 [2] 5e b0 [2] 58 85 [2] 76 85 [2] 49 99 }

  condition:
    any of them
}