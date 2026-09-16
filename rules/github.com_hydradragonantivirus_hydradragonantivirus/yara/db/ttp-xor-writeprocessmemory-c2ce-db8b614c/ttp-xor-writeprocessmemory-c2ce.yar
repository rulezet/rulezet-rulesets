rule TTP_XOR_WriteProcessMemory_c2ce {
  strings:
    $key_c2ce = { 95 bc [2] a7 9e [2] a1 ab [2] 8f ab [2] b0 b7 }

  condition:
    any of them
}