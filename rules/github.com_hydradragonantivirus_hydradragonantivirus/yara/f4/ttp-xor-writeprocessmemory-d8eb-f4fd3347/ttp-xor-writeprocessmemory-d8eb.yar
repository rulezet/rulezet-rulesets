rule TTP_XOR_WriteProcessMemory_d8eb {
  strings:
    $key_d8eb = { 8f 99 [2] bd bb [2] bb 8e [2] 95 8e [2] aa 92 }

  condition:
    any of them
}