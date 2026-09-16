rule TTP_XOR_WriteProcessMemory_3b4c {
  strings:
    $key_3b4c = { 6c 3e [2] 5e 1c [2] 58 29 [2] 76 29 [2] 49 35 }

  condition:
    any of them
}