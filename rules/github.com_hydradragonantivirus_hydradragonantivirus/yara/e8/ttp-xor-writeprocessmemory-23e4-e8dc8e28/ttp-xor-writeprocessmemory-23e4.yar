rule TTP_XOR_WriteProcessMemory_23e4 {
  strings:
    $key_23e4 = { 74 96 [2] 46 b4 [2] 40 81 [2] 6e 81 [2] 51 9d }

  condition:
    any of them
}