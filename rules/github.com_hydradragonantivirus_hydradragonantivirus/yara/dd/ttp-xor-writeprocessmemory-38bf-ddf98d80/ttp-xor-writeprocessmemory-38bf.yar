rule TTP_XOR_WriteProcessMemory_38bf {
  strings:
    $key_38bf = { 6f cd [2] 5d ef [2] 5b da [2] 75 da [2] 4a c6 }

  condition:
    any of them
}