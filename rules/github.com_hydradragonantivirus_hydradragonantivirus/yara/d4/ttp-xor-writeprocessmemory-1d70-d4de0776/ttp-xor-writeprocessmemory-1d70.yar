rule TTP_XOR_WriteProcessMemory_1d70 {
  strings:
    $key_1d70 = { 4a 02 [2] 78 20 [2] 7e 15 [2] 50 15 [2] 6f 09 }

  condition:
    any of them
}