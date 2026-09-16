rule TTP_XOR_WriteProcessMemory_e558 {
  strings:
    $key_e558 = { b2 2a [2] 80 08 [2] 86 3d [2] a8 3d [2] 97 21 }

  condition:
    any of them
}