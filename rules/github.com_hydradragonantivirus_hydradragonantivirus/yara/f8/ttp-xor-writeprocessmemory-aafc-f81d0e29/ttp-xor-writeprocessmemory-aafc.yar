rule TTP_XOR_WriteProcessMemory_aafc {
  strings:
    $key_aafc = { fd 8e [2] cf ac [2] c9 99 [2] e7 99 [2] d8 85 }

  condition:
    any of them
}