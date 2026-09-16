rule TTP_XOR_WriteProcessMemory_ee8b {
  strings:
    $key_ee8b = { b9 f9 [2] 8b db [2] 8d ee [2] a3 ee [2] 9c f2 }

  condition:
    any of them
}