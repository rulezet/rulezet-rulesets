rule TTP_XOR_WriteProcessMemory_451b {
  strings:
    $key_451b = { 12 69 [2] 20 4b [2] 26 7e [2] 08 7e [2] 37 62 }

  condition:
    any of them
}