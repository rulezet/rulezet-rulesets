rule TTP_XOR_WriteProcessMemory_2231 {
  strings:
    $key_2231 = { 75 43 [2] 47 61 [2] 41 54 [2] 6f 54 [2] 50 48 }

  condition:
    any of them
}