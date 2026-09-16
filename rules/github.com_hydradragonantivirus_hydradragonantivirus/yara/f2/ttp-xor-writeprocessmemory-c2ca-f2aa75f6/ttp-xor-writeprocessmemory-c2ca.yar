rule TTP_XOR_WriteProcessMemory_c2ca {
  strings:
    $key_c2ca = { 95 b8 [2] a7 9a [2] a1 af [2] 8f af [2] b0 b3 }

  condition:
    any of them
}