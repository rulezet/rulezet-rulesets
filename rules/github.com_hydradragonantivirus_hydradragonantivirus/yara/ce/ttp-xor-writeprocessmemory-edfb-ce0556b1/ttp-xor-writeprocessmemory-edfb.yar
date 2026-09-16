rule TTP_XOR_WriteProcessMemory_edfb {
  strings:
    $key_edfb = { ba 89 [2] 88 ab [2] 8e 9e [2] a0 9e [2] 9f 82 }

  condition:
    any of them
}