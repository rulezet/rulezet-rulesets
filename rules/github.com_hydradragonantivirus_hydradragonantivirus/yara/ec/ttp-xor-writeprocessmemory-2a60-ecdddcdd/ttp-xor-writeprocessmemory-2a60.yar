rule TTP_XOR_WriteProcessMemory_2a60 {
  strings:
    $key_2a60 = { 7d 12 [2] 4f 30 [2] 49 05 [2] 67 05 [2] 58 19 }

  condition:
    any of them
}