rule TTP_XOR_WriteProcessMemory_2261 {
  strings:
    $key_2261 = { 75 13 [2] 47 31 [2] 41 04 [2] 6f 04 [2] 50 18 }

  condition:
    any of them
}