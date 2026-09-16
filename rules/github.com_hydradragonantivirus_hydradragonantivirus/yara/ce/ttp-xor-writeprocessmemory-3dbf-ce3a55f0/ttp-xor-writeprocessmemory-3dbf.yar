rule TTP_XOR_WriteProcessMemory_3dbf {
  strings:
    $key_3dbf = { 6a cd [2] 58 ef [2] 5e da [2] 70 da [2] 4f c6 }

  condition:
    any of them
}