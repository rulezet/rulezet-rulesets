rule TTP_XOR_WriteProcessMemory_d758 {
  strings:
    $key_d758 = { 80 2a [2] b2 08 [2] b4 3d [2] 9a 3d [2] a5 21 }

  condition:
    any of them
}