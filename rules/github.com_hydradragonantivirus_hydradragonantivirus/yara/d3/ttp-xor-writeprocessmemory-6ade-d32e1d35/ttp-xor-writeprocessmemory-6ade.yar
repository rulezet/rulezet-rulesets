rule TTP_XOR_WriteProcessMemory_6ade {
  strings:
    $key_6ade = { 3d ac [2] 0f 8e [2] 09 bb [2] 27 bb [2] 18 a7 }

  condition:
    any of them
}