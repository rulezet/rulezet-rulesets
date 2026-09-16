rule TTP_XOR_WriteProcessMemory_006c {
  strings:
    $key_006c = { 57 1e [2] 65 3c [2] 63 09 [2] 4d 09 [2] 72 15 }

  condition:
    any of them
}