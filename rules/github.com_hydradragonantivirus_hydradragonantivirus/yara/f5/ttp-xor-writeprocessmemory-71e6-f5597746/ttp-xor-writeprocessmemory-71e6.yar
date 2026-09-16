rule TTP_XOR_WriteProcessMemory_71e6 {
  strings:
    $key_71e6 = { 26 94 [2] 14 b6 [2] 12 83 [2] 3c 83 [2] 03 9f }

  condition:
    any of them
}