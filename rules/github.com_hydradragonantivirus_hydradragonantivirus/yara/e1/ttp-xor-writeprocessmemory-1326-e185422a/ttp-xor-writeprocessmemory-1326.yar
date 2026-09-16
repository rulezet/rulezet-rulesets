rule TTP_XOR_WriteProcessMemory_1326 {
  strings:
    $key_1326 = { 44 54 [2] 76 76 [2] 70 43 [2] 5e 43 [2] 61 5f }

  condition:
    any of them
}