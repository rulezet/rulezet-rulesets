rule TTP_XOR_WriteProcessMemory_6226 {
  strings:
    $key_6226 = { 35 54 [2] 07 76 [2] 01 43 [2] 2f 43 [2] 10 5f }

  condition:
    any of them
}