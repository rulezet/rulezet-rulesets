rule TTP_XOR_WriteProcessMemory_32e4 {
  strings:
    $key_32e4 = { 65 96 [2] 57 b4 [2] 51 81 [2] 7f 81 [2] 40 9d }

  condition:
    any of them
}