rule TTP_XOR_WriteProcessMemory_1cde {
  strings:
    $key_1cde = { 4b ac [2] 79 8e [2] 7f bb [2] 51 bb [2] 6e a7 }

  condition:
    any of them
}