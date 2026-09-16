rule TTP_XOR_WriteProcessMemory_f53b {
  strings:
    $key_f53b = { a2 49 [2] 90 6b [2] 96 5e [2] b8 5e [2] 87 42 }

  condition:
    any of them
}