rule TTP_XOR_WriteProcessMemory_d7ff {
  strings:
    $key_d7ff = { 80 8d [2] b2 af [2] b4 9a [2] 9a 9a [2] a5 86 }

  condition:
    any of them
}