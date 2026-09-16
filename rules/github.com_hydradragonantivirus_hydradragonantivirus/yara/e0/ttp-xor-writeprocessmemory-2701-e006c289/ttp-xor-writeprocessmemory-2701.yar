rule TTP_XOR_WriteProcessMemory_2701 {
  strings:
    $key_2701 = { 70 73 [2] 42 51 [2] 44 64 [2] 6a 64 [2] 55 78 }

  condition:
    any of them
}