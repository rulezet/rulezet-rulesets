rule TTP_XOR_WriteProcessMemory_326b {
  strings:
    $key_326b = { 65 19 [2] 57 3b [2] 51 0e [2] 7f 0e [2] 40 12 }

  condition:
    any of them
}