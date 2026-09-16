rule TTP_XOR_WriteProcessMemory_131c {
  strings:
    $key_131c = { 44 6e [2] 76 4c [2] 70 79 [2] 5e 79 [2] 61 65 }

  condition:
    any of them
}