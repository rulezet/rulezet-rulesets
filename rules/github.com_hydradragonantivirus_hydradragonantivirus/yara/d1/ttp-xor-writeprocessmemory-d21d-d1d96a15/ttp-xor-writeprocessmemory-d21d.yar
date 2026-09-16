rule TTP_XOR_WriteProcessMemory_d21d {
  strings:
    $key_d21d = { 85 6f [2] b7 4d [2] b1 78 [2] 9f 78 [2] a0 64 }

  condition:
    any of them
}