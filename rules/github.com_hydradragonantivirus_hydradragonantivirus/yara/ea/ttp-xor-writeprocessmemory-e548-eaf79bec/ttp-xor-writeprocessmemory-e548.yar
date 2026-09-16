rule TTP_XOR_WriteProcessMemory_e548 {
  strings:
    $key_e548 = { b2 3a [2] 80 18 [2] 86 2d [2] a8 2d [2] 97 31 }

  condition:
    any of them
}