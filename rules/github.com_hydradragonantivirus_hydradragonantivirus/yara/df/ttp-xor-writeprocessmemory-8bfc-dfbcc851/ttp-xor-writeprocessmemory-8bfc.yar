rule TTP_XOR_WriteProcessMemory_8bfc {
  strings:
    $key_8bfc = { dc 8e [2] ee ac [2] e8 99 [2] c6 99 [2] f9 85 }

  condition:
    any of them
}