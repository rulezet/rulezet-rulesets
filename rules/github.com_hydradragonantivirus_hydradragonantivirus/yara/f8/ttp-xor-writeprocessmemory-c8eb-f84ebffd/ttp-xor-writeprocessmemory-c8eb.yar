rule TTP_XOR_WriteProcessMemory_c8eb {
  strings:
    $key_c8eb = { 9f 99 [2] ad bb [2] ab 8e [2] 85 8e [2] ba 92 }

  condition:
    any of them
}