rule TTP_XOR_WriteProcessMemory_5ad9 {
  strings:
    $key_5ad9 = { 0d ab [2] 3f 89 [2] 39 bc [2] 17 bc [2] 28 a0 }

  condition:
    any of them
}