rule TTP_XOR_WriteProcessMemory_c0ff {
  strings:
    $key_c0ff = { 97 8d [2] a5 af [2] a3 9a [2] 8d 9a [2] b2 86 }

  condition:
    any of them
}