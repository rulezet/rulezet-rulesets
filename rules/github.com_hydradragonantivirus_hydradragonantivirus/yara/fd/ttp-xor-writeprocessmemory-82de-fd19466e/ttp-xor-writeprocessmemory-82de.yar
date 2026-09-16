rule TTP_XOR_WriteProcessMemory_82de {
  strings:
    $key_82de = { d5 ac [2] e7 8e [2] e1 bb [2] cf bb [2] f0 a7 }

  condition:
    any of them
}