rule TTP_XOR_WriteProcessMemory_78bf {
  strings:
    $key_78bf = { 2f cd [2] 1d ef [2] 1b da [2] 35 da [2] 0a c6 }

  condition:
    any of them
}