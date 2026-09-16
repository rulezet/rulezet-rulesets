rule TTP_XOR_WriteProcessMemory_24e4 {
  strings:
    $key_24e4 = { 73 96 [2] 41 b4 [2] 47 81 [2] 69 81 [2] 56 9d }

  condition:
    any of them
}