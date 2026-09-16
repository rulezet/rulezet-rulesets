rule TTP_XOR_WriteProcessMemory_0c5b {
  strings:
    $key_0c5b = { 5b 29 [2] 69 0b [2] 6f 3e [2] 41 3e [2] 7e 22 }

  condition:
    any of them
}