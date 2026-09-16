rule TTP_XOR_WriteProcessMemory_eada {
  strings:
    $key_eada = { bd a8 [2] 8f 8a [2] 89 bf [2] a7 bf [2] 98 a3 }

  condition:
    any of them
}