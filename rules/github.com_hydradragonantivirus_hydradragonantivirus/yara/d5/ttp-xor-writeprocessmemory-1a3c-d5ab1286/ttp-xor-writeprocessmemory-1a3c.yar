rule TTP_XOR_WriteProcessMemory_1a3c {
  strings:
    $key_1a3c = { 4d 4e [2] 7f 6c [2] 79 59 [2] 57 59 [2] 68 45 }

  condition:
    any of them
}