rule TTP_XOR_WriteProcessMemory_c64d {
  strings:
    $key_c64d = { 91 3f [2] a3 1d [2] a5 28 [2] 8b 28 [2] b4 34 }

  condition:
    any of them
}