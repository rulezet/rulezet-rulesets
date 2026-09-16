rule TTP_XOR_WriteProcessMemory_004c {
  strings:
    $key_004c = { 57 3e [2] 65 1c [2] 63 29 [2] 4d 29 [2] 72 35 }

  condition:
    any of them
}