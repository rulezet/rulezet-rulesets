rule TTP_XOR_WriteProcessMemory_0116 {
  strings:
    $key_0116 = { 56 64 [2] 64 46 [2] 62 73 [2] 4c 73 [2] 73 6f }

  condition:
    any of them
}