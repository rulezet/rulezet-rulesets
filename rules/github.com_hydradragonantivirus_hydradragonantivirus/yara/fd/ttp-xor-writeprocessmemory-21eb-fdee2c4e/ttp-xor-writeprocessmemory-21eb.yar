rule TTP_XOR_WriteProcessMemory_21eb {
  strings:
    $key_21eb = { 76 99 [2] 44 bb [2] 42 8e [2] 6c 8e [2] 53 92 }

  condition:
    any of them
}