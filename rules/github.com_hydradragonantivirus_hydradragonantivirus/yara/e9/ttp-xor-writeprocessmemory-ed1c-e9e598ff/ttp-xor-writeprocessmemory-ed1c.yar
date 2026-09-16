rule TTP_XOR_WriteProcessMemory_ed1c {
  strings:
    $key_ed1c = { ba 6e [2] 88 4c [2] 8e 79 [2] a0 79 [2] 9f 65 }

  condition:
    any of them
}