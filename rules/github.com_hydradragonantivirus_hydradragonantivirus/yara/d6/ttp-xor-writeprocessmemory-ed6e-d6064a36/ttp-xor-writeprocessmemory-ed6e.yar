rule TTP_XOR_WriteProcessMemory_ed6e {
  strings:
    $key_ed6e = { ba 1c [2] 88 3e [2] 8e 0b [2] a0 0b [2] 9f 17 }

  condition:
    any of them
}