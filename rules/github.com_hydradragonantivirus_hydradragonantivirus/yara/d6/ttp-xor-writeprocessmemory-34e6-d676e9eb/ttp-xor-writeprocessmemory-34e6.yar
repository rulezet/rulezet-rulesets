rule TTP_XOR_WriteProcessMemory_34e6 {
  strings:
    $key_34e6 = { 63 94 [2] 51 b6 [2] 57 83 [2] 79 83 [2] 46 9f }

  condition:
    any of them
}