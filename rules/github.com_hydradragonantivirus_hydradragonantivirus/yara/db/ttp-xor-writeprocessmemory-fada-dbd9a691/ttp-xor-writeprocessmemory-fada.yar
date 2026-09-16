rule TTP_XOR_WriteProcessMemory_fada {
  strings:
    $key_fada = { ad a8 [2] 9f 8a [2] 99 bf [2] b7 bf [2] 88 a3 }

  condition:
    any of them
}