rule TTP_XOR_WriteProcessMemory_4326 {
  strings:
    $key_4326 = { 14 54 [2] 26 76 [2] 20 43 [2] 0e 43 [2] 31 5f }

  condition:
    any of them
}