rule TTP_XOR_WriteProcessMemory_0ade {
  strings:
    $key_0ade = { 5d ac [2] 6f 8e [2] 69 bb [2] 47 bb [2] 78 a7 }

  condition:
    any of them
}