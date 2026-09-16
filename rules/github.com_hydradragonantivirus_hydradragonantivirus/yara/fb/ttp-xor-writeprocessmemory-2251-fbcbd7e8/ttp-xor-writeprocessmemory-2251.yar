rule TTP_XOR_WriteProcessMemory_2251 {
  strings:
    $key_2251 = { 75 23 [2] 47 01 [2] 41 34 [2] 6f 34 [2] 50 28 }

  condition:
    any of them
}