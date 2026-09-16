rule TTP_XOR_WriteProcessMemory_c458 {
  strings:
    $key_c458 = { 93 2a [2] a1 08 [2] a7 3d [2] 89 3d [2] b6 21 }

  condition:
    any of them
}