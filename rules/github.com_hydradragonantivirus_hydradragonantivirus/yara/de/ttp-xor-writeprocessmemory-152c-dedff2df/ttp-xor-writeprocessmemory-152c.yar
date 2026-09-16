rule TTP_XOR_WriteProcessMemory_152c {
  strings:
    $key_152c = { 42 5e [2] 70 7c [2] 76 49 [2] 58 49 [2] 67 55 }

  condition:
    any of them
}