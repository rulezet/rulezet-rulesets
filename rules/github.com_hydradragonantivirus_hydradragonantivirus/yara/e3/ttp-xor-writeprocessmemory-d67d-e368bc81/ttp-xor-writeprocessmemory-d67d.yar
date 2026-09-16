rule TTP_XOR_WriteProcessMemory_d67d {
  strings:
    $key_d67d = { 81 0f [2] b3 2d [2] b5 18 [2] 9b 18 [2] a4 04 }

  condition:
    any of them
}