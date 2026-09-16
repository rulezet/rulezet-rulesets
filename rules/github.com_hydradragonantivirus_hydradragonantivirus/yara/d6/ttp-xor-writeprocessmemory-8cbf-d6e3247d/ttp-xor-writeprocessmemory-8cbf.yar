rule TTP_XOR_WriteProcessMemory_8cbf {
  strings:
    $key_8cbf = { db cd [2] e9 ef [2] ef da [2] c1 da [2] fe c6 }

  condition:
    any of them
}