rule TTP_XOR_WriteProcessMemory_1d10 {
  strings:
    $key_1d10 = { 4a 62 [2] 78 40 [2] 7e 75 [2] 50 75 [2] 6f 69 }

  condition:
    any of them
}