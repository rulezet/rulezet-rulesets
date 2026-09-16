rule TTP_XOR_WriteProcessMemory_e76d {
  strings:
    $key_e76d = { b0 1f [2] 82 3d [2] 84 08 [2] aa 08 [2] 95 14 }

  condition:
    any of them
}