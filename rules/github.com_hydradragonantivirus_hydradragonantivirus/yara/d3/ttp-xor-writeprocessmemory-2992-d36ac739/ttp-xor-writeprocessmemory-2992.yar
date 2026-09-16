rule TTP_XOR_WriteProcessMemory_2992 {
  strings:
    $key_2992 = { 7e e0 [2] 4c c2 [2] 4a f7 [2] 64 f7 [2] 5b eb }

  condition:
    any of them
}