rule TTP_XOR_WriteProcessMemory_c2da {
  strings:
    $key_c2da = { 95 a8 [2] a7 8a [2] a1 bf [2] 8f bf [2] b0 a3 }

  condition:
    any of them
}