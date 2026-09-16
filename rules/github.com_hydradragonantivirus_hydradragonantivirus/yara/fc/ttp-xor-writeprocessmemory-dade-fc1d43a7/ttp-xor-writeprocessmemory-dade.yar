rule TTP_XOR_WriteProcessMemory_dade {
  strings:
    $key_dade = { 8d ac [2] bf 8e [2] b9 bb [2] 97 bb [2] a8 a7 }

  condition:
    any of them
}