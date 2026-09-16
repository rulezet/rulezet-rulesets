rule TTP_XOR_WriteProcessMemory_fc3d {
  strings:
    $key_fc3d = { ab 4f [2] 99 6d [2] 9f 58 [2] b1 58 [2] 8e 44 }

  condition:
    any of them
}