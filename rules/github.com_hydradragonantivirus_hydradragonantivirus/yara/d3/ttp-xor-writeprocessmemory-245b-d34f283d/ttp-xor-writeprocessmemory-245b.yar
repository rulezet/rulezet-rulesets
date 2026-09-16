rule TTP_XOR_WriteProcessMemory_245b {
  strings:
    $key_245b = { 73 29 [2] 41 0b [2] 47 3e [2] 69 3e [2] 56 22 }

  condition:
    any of them
}