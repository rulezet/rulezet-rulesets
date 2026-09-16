rule TTP_XOR_WriteProcessMemory_d77f {
  strings:
    $key_d77f = { 80 0d [2] b2 2f [2] b4 1a [2] 9a 1a [2] a5 06 }

  condition:
    any of them
}