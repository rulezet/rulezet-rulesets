rule TTP_XOR_WriteProcessMemory_59b5 {
  strings:
    $key_59b5 = { 0e c7 [2] 3c e5 [2] 3a d0 [2] 14 d0 [2] 2b cc }

  condition:
    any of them
}