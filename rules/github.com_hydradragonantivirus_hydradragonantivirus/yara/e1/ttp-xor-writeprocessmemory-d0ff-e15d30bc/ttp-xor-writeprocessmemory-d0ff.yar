rule TTP_XOR_WriteProcessMemory_d0ff {
  strings:
    $key_d0ff = { 87 8d [2] b5 af [2] b3 9a [2] 9d 9a [2] a2 86 }

  condition:
    any of them
}