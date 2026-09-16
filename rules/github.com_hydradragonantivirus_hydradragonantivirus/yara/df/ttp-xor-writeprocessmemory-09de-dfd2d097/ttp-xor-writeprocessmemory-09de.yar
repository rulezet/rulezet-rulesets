rule TTP_XOR_WriteProcessMemory_09de {
  strings:
    $key_09de = { 5e ac [2] 6c 8e [2] 6a bb [2] 44 bb [2] 7b a7 }

  condition:
    any of them
}