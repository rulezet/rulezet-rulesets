rule TTP_XOR_WriteProcessMemory_fa6d {
  strings:
    $key_fa6d = { ad 1f [2] 9f 3d [2] 99 08 [2] b7 08 [2] 88 14 }

  condition:
    any of them
}