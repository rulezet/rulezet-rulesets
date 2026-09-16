rule TTP_XOR_WriteProcessMemory_0151 {
  strings:
    $key_0151 = { 56 23 [2] 64 01 [2] 62 34 [2] 4c 34 [2] 73 28 }

  condition:
    any of them
}