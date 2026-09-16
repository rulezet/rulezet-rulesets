rule TTP_XOR_WriteProcessMemory_c8da {
  strings:
    $key_c8da = { 9f a8 [2] ad 8a [2] ab bf [2] 85 bf [2] ba a3 }

  condition:
    any of them
}