rule TTP_XOR_WriteProcessMemory_ed4c {
  strings:
    $key_ed4c = { ba 3e [2] 88 1c [2] 8e 29 [2] a0 29 [2] 9f 35 }

  condition:
    any of them
}