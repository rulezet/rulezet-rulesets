rule TTP_XOR_WriteProcessMemory_79b3 {
  strings:
    $key_79b3 = { 2e c1 [2] 1c e3 [2] 1a d6 [2] 34 d6 [2] 0b ca }

  condition:
    any of them
}