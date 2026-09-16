rule TTP_XOR_WriteProcessMemory_e748 {
  strings:
    $key_e748 = { b0 3a [2] 82 18 [2] 84 2d [2] aa 2d [2] 95 31 }

  condition:
    any of them
}