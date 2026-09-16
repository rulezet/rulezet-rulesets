rule TTP_XOR_WriteProcessMemory_d1ca {
  strings:
    $key_d1ca = { 86 b8 [2] b4 9a [2] b2 af [2] 9c af [2] a3 b3 }

  condition:
    any of them
}