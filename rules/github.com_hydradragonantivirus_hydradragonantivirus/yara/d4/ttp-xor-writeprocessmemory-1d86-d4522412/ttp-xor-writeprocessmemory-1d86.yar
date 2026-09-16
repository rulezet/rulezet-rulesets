rule TTP_XOR_WriteProcessMemory_1d86 {
  strings:
    $key_1d86 = { 4a f4 [2] 78 d6 [2] 7e e3 [2] 50 e3 [2] 6f ff }

  condition:
    any of them
}