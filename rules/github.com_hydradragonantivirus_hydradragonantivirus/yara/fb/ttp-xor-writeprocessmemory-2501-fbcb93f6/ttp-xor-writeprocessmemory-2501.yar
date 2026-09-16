rule TTP_XOR_WriteProcessMemory_2501 {
  strings:
    $key_2501 = { 72 73 [2] 40 51 [2] 46 64 [2] 68 64 [2] 57 78 }

  condition:
    any of them
}