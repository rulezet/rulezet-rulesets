rule TTP_XOR_WriteProcessMemory_28bf {
  strings:
    $key_28bf = { 7f cd [2] 4d ef [2] 4b da [2] 65 da [2] 5a c6 }

  condition:
    any of them
}