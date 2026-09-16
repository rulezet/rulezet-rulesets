rule TTP_XOR_WriteProcessMemory_e508 {
  strings:
    $key_e508 = { b2 7a [2] 80 58 [2] 86 6d [2] a8 6d [2] 97 71 }

  condition:
    any of them
}