rule TTP_XOR_WriteProcessMemory_80de {
  strings:
    $key_80de = { d7 ac [2] e5 8e [2] e3 bb [2] cd bb [2] f2 a7 }

  condition:
    any of them
}