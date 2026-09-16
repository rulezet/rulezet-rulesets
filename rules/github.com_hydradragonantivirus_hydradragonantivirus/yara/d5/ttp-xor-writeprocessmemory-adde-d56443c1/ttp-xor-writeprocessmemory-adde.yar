rule TTP_XOR_WriteProcessMemory_adde {
  strings:
    $key_adde = { fa ac [2] c8 8e [2] ce bb [2] e0 bb [2] df a7 }

  condition:
    any of them
}