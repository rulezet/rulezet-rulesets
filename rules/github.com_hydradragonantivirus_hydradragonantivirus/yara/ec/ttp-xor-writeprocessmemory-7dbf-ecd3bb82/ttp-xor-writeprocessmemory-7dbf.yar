rule TTP_XOR_WriteProcessMemory_7dbf {
  strings:
    $key_7dbf = { 2a cd [2] 18 ef [2] 1e da [2] 30 da [2] 0f c6 }

  condition:
    any of them
}