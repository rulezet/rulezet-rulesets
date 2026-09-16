rule TTP_XOR_WriteProcessMemory_c71d {
  strings:
    $key_c71d = { 90 6f [2] a2 4d [2] a4 78 [2] 8a 78 [2] b5 64 }

  condition:
    any of them
}