rule TTP_XOR_WriteProcessMemory_71e4 {
  strings:
    $key_71e4 = { 26 96 [2] 14 b4 [2] 12 81 [2] 3c 81 [2] 03 9d }

  condition:
    any of them
}