rule TTP_XOR_WriteProcessMemory_2a30 {
  strings:
    $key_2a30 = { 7d 42 [2] 4f 60 [2] 49 55 [2] 67 55 [2] 58 49 }

  condition:
    any of them
}