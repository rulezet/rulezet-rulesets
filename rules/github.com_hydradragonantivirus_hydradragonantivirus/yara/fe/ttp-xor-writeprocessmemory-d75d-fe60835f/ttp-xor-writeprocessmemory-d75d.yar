rule TTP_XOR_WriteProcessMemory_d75d {
  strings:
    $key_d75d = { 80 2f [2] b2 0d [2] b4 38 [2] 9a 38 [2] a5 24 }

  condition:
    any of them
}