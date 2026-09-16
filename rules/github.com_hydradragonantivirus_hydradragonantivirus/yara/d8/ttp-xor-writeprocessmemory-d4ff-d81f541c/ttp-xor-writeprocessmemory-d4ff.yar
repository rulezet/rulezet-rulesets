rule TTP_XOR_WriteProcessMemory_d4ff {
  strings:
    $key_d4ff = { 83 8d [2] b1 af [2] b7 9a [2] 99 9a [2] a6 86 }

  condition:
    any of them
}