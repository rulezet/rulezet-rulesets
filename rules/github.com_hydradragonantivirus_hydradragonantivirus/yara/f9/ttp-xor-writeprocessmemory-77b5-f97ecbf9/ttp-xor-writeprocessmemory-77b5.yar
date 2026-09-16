rule TTP_XOR_WriteProcessMemory_77b5 {
  strings:
    $key_77b5 = { 20 c7 [2] 12 e5 [2] 14 d0 [2] 3a d0 [2] 05 cc }

  condition:
    any of them
}