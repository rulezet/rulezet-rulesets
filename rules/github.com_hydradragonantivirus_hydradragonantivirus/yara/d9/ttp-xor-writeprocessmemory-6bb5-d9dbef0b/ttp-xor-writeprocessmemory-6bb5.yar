rule TTP_XOR_WriteProcessMemory_6bb5 {
  strings:
    $key_6bb5 = { 3c c7 [2] 0e e5 [2] 08 d0 [2] 26 d0 [2] 19 cc }

  condition:
    any of them
}