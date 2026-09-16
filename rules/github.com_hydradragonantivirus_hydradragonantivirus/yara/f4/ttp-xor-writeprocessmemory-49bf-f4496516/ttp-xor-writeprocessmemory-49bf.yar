rule TTP_XOR_WriteProcessMemory_49bf {
  strings:
    $key_49bf = { 1e cd [2] 2c ef [2] 2a da [2] 04 da [2] 3b c6 }

  condition:
    any of them
}