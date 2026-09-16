rule TTP_XOR_WriteProcessMemory_eb3d {
  strings:
    $key_eb3d = { bc 4f [2] 8e 6d [2] 88 58 [2] a6 58 [2] 99 44 }

  condition:
    any of them
}