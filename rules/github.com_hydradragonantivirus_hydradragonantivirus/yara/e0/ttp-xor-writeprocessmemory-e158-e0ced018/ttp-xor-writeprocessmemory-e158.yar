rule TTP_XOR_WriteProcessMemory_e158 {
  strings:
    $key_e158 = { b6 2a [2] 84 08 [2] 82 3d [2] ac 3d [2] 93 21 }

  condition:
    any of them
}