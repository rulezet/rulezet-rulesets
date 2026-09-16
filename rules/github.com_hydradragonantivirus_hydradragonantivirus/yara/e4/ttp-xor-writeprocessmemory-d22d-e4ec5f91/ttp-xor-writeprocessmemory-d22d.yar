rule TTP_XOR_WriteProcessMemory_d22d {
  strings:
    $key_d22d = { 85 5f [2] b7 7d [2] b1 48 [2] 9f 48 [2] a0 54 }

  condition:
    any of them
}