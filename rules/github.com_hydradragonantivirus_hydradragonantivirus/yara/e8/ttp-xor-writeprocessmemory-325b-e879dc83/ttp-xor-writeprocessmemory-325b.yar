rule TTP_XOR_WriteProcessMemory_325b {
  strings:
    $key_325b = { 65 29 [2] 57 0b [2] 51 3e [2] 7f 3e [2] 40 22 }

  condition:
    any of them
}