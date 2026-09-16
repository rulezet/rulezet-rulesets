rule TTP_XOR_WriteProcessMemory_d2ca {
  strings:
    $key_d2ca = { 85 b8 [2] b7 9a [2] b1 af [2] 9f af [2] a0 b3 }

  condition:
    any of them
}