rule TTP_XOR_WriteProcessMemory_e16d {
  strings:
    $key_e16d = { b6 1f [2] 84 3d [2] 82 08 [2] ac 08 [2] 93 14 }

  condition:
    any of them
}