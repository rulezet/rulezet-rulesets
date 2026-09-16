rule TTP_XOR_WriteProcessMemory_ed69 {
  strings:
    $key_ed69 = { ba 1b [2] 88 39 [2] 8e 0c [2] a0 0c [2] 9f 10 }

  condition:
    any of them
}