rule TTP_XOR_WriteProcessMemory_e3eb {
  strings:
    $key_e3eb = { b4 99 [2] 86 bb [2] 80 8e [2] ae 8e [2] 91 92 }

  condition:
    any of them
}