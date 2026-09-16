rule TTP_XOR_WriteProcessMemory_c46d {
  strings:
    $key_c46d = { 93 1f [2] a1 3d [2] a7 08 [2] 89 08 [2] b6 14 }

  condition:
    any of them
}