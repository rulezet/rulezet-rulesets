rule TTP_XOR_WriteProcessMemory_1d31 {
  strings:
    $key_1d31 = { 4a 43 [2] 78 61 [2] 7e 54 [2] 50 54 [2] 6f 48 }

  condition:
    any of them
}