rule TTP_XOR_WriteProcessMemory_e56d {
  strings:
    $key_e56d = { b2 1f [2] 80 3d [2] 86 08 [2] a8 08 [2] 97 14 }

  condition:
    any of them
}