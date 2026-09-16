rule TTP_XOR_WriteProcessMemory_87de {
  strings:
    $key_87de = { d0 ac [2] e2 8e [2] e4 bb [2] ca bb [2] f5 a7 }

  condition:
    any of them
}