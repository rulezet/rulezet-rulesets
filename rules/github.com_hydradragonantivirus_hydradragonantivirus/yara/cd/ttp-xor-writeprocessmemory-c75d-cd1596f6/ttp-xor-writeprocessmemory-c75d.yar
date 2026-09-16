rule TTP_XOR_WriteProcessMemory_c75d {
  strings:
    $key_c75d = { 90 2f [2] a2 0d [2] a4 38 [2] 8a 38 [2] b5 24 }

  condition:
    any of them
}