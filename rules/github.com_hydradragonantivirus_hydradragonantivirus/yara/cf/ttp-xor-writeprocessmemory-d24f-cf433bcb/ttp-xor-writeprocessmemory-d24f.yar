rule TTP_XOR_WriteProcessMemory_d24f {
  strings:
    $key_d24f = { 85 3d [2] b7 1f [2] b1 2a [2] 9f 2a [2] a0 36 }

  condition:
    any of them
}