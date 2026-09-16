rule TTP_XOR_WriteProcessMemory_69bf {
  strings:
    $key_69bf = { 3e cd [2] 0c ef [2] 0a da [2] 24 da [2] 1b c6 }

  condition:
    any of them
}