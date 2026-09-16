rule TTP_XOR_WriteProcessMemory_3b20 {
  strings:
    $key_3b20 = { 6c 52 [2] 5e 70 [2] 58 45 [2] 76 45 [2] 49 59 }

  condition:
    any of them
}