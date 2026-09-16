rule TTP_XOR_WriteProcessMemory_003c {
  strings:
    $key_003c = { 57 4e [2] 65 6c [2] 63 59 [2] 4d 59 [2] 72 45 }

  condition:
    any of them
}