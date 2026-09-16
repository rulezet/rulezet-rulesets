rule TTP_XOR_WriteProcessMemory_d4ca {
  strings:
    $key_d4ca = { 83 b8 [2] b1 9a [2] b7 af [2] 99 af [2] a6 b3 }

  condition:
    any of them
}