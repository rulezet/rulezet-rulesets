rule TTP_XOR_WriteProcessMemory_f9de {
  strings:
    $key_f9de = { ae ac [2] 9c 8e [2] 9a bb [2] b4 bb [2] 8b a7 }

  condition:
    any of them
}