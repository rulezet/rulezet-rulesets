rule TTP_XOR_WriteProcessMemory_2200 {
  strings:
    $key_2200 = { 75 72 [2] 47 50 [2] 41 65 [2] 6f 65 [2] 50 79 }

  condition:
    any of them
}