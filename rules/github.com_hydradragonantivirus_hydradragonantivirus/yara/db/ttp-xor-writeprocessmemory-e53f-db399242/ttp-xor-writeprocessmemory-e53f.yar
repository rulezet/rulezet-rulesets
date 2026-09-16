rule TTP_XOR_WriteProcessMemory_e53f {
  strings:
    $key_e53f = { b2 4d [2] 80 6f [2] 86 5a [2] a8 5a [2] 97 46 }

  condition:
    any of them
}