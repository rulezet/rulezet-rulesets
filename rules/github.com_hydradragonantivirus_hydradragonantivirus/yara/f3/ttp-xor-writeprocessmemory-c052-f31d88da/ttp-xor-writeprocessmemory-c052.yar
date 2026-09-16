rule TTP_XOR_WriteProcessMemory_c052 {
  strings:
    $key_c052 = { 97 20 [2] a5 02 [2] a3 37 [2] 8d 37 [2] b2 2b }

  condition:
    any of them
}