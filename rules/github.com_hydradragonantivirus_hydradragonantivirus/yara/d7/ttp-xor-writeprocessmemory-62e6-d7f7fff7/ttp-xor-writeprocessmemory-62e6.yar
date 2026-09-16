rule TTP_XOR_WriteProcessMemory_62e6 {
  strings:
    $key_62e6 = { 35 94 [2] 07 b6 [2] 01 83 [2] 2f 83 [2] 10 9f }

  condition:
    any of them
}