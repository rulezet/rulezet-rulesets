rule TTP_XOR_WriteProcessMemory_e553 {
  strings:
    $key_e553 = { b2 21 [2] 80 03 [2] 86 36 [2] a8 36 [2] 97 2a }

  condition:
    any of them
}