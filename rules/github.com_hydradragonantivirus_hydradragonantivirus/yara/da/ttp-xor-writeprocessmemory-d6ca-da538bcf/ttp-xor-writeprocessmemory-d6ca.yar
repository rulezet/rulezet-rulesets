rule TTP_XOR_WriteProcessMemory_d6ca {
  strings:
    $key_d6ca = { 81 b8 [2] b3 9a [2] b5 af [2] 9b af [2] a4 b3 }

  condition:
    any of them
}