rule TTP_XOR_WriteProcessMemory_3b9d {
  strings:
    $key_3b9d = { 6c ef [2] 5e cd [2] 58 f8 [2] 76 f8 [2] 49 e4 }

  condition:
    any of them
}