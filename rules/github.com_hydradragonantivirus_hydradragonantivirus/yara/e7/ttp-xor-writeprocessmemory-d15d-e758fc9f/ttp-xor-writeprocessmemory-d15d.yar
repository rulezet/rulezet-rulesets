rule TTP_XOR_WriteProcessMemory_d15d {
  strings:
    $key_d15d = { 86 2f [2] b4 0d [2] b2 38 [2] 9c 38 [2] a3 24 }

  condition:
    any of them
}