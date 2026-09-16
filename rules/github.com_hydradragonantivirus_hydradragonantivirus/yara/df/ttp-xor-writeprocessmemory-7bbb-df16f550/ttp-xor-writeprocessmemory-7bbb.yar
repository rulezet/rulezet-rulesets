rule TTP_XOR_WriteProcessMemory_7bbb {
  strings:
    $key_7bbb = { 2c c9 [2] 1e eb [2] 18 de [2] 36 de [2] 09 c2 }

  condition:
    any of them
}