rule TTP_XOR_WriteProcessMemory_48eb {
  strings:
    $key_48eb = { 1f 99 [2] 2d bb [2] 2b 8e [2] 05 8e [2] 3a 92 }

  condition:
    any of them
}