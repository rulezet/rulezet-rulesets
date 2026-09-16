rule TTP_XOR_WriteProcessMemory_6d4c {
  strings:
    $key_6d4c = { 3a 3e [2] 08 1c [2] 0e 29 [2] 20 29 [2] 1f 35 }

  condition:
    any of them
}