rule TTP_XOR_WriteProcessMemory_fa58 {
  strings:
    $key_fa58 = { ad 2a [2] 9f 08 [2] 99 3d [2] b7 3d [2] 88 21 }

  condition:
    any of them
}