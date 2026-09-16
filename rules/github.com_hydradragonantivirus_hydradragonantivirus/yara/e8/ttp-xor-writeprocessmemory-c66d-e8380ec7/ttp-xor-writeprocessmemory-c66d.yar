rule TTP_XOR_WriteProcessMemory_c66d {
  strings:
    $key_c66d = { 91 1f [2] a3 3d [2] a5 08 [2] 8b 08 [2] b4 14 }

  condition:
    any of them
}