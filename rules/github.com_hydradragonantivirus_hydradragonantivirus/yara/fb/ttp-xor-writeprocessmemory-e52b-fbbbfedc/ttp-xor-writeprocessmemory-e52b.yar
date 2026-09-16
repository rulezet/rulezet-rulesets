rule TTP_XOR_WriteProcessMemory_e52b {
  strings:
    $key_e52b = { b2 59 [2] 80 7b [2] 86 4e [2] a8 4e [2] 97 52 }

  condition:
    any of them
}