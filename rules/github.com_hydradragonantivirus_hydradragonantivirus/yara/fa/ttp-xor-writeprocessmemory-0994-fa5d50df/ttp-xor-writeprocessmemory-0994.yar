rule TTP_XOR_WriteProcessMemory_0994 {
  strings:
    $key_0994 = { 5e e6 [2] 6c c4 [2] 6a f1 [2] 44 f1 [2] 7b ed }

  condition:
    any of them
}