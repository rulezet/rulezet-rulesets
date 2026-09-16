rule TTP_XOR_WriteProcessMemory_d41d {
  strings:
    $key_d41d = { 83 6f [2] b1 4d [2] b7 78 [2] 99 78 [2] a6 64 }

  condition:
    any of them
}