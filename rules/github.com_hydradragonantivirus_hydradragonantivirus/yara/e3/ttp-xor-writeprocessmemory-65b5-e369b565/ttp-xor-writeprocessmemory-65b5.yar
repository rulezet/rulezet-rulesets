rule TTP_XOR_WriteProcessMemory_65b5 {
  strings:
    $key_65b5 = { 32 c7 [2] 00 e5 [2] 06 d0 [2] 28 d0 [2] 17 cc }

  condition:
    any of them
}