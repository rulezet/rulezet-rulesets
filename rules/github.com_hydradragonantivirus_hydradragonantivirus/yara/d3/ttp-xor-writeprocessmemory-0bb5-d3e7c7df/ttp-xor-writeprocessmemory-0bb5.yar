rule TTP_XOR_WriteProcessMemory_0bb5 {
  strings:
    $key_0bb5 = { 5c c7 [2] 6e e5 [2] 68 d0 [2] 46 d0 [2] 79 cc }

  condition:
    any of them
}