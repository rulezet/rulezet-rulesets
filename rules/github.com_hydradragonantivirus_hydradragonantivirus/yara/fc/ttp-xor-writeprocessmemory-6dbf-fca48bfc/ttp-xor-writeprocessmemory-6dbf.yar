rule TTP_XOR_WriteProcessMemory_6dbf {
  strings:
    $key_6dbf = { 3a cd [2] 08 ef [2] 0e da [2] 20 da [2] 1f c6 }

  condition:
    any of them
}