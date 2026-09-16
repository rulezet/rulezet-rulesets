rule TTP_XOR_WriteProcessMemory_97de {
  strings:
    $key_97de = { c0 ac [2] f2 8e [2] f4 bb [2] da bb [2] e5 a7 }

  condition:
    any of them
}