rule TTP_XOR_WriteProcessMemory_7d86 {
  strings:
    $key_7d86 = { 2a f4 [2] 18 d6 [2] 1e e3 [2] 30 e3 [2] 0f ff }

  condition:
    any of them
}