rule TTP_XOR_WriteProcessMemory_d8fc {
  strings:
    $key_d8fc = { 8f 8e [2] bd ac [2] bb 99 [2] 95 99 [2] aa 85 }

  condition:
    any of them
}