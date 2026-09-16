rule TTP_XOR_WriteProcessMemory_69b2 {
  strings:
    $key_69b2 = { 3e c0 [2] 0c e2 [2] 0a d7 [2] 24 d7 [2] 1b cb }

  condition:
    any of them
}