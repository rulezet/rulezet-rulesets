rule TTP_XOR_WriteProcessMemory_002c {
  strings:
    $key_002c = { 57 5e [2] 65 7c [2] 63 49 [2] 4d 49 [2] 72 55 }

  condition:
    any of them
}