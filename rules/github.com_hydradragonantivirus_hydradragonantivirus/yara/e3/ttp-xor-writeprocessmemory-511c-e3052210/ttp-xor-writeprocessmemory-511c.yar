rule TTP_XOR_WriteProcessMemory_511c {
  strings:
    $key_511c = { 06 6e [2] 34 4c [2] 32 79 [2] 1c 79 [2] 23 65 }

  condition:
    any of them
}