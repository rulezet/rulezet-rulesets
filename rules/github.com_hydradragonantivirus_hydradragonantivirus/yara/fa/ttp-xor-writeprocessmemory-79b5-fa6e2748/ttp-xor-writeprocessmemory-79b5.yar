rule TTP_XOR_WriteProcessMemory_79b5 {
  strings:
    $key_79b5 = { 2e c7 [2] 1c e5 [2] 1a d0 [2] 34 d0 [2] 0b cc }

  condition:
    any of them
}