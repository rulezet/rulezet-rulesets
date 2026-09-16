rule TTP_XOR_WriteProcessMemory_0155 {
  strings:
    $key_0155 = { 56 27 [2] 64 05 [2] 62 30 [2] 4c 30 [2] 73 2c }

  condition:
    any of them
}