rule TTP_XOR_WriteProcessMemory_d66d {
  strings:
    $key_d66d = { 81 1f [2] b3 3d [2] b5 08 [2] 9b 08 [2] a4 14 }

  condition:
    any of them
}