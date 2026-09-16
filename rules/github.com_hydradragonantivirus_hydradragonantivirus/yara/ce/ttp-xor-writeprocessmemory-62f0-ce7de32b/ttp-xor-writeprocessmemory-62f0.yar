rule TTP_XOR_WriteProcessMemory_62f0 {
  strings:
    $key_62f0 = { 35 82 [2] 07 a0 [2] 01 95 [2] 2f 95 [2] 10 89 }

  condition:
    any of them
}