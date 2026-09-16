rule TTP_XOR_WriteProcessMemory_5ad2 {
  strings:
    $key_5ad2 = { 0d a0 [2] 3f 82 [2] 39 b7 [2] 17 b7 [2] 28 ab }

  condition:
    any of them
}