rule TTP_XOR_WriteProcessMemory_462b {
  strings:
    $key_462b = { 11 59 [2] 23 7b [2] 25 4e [2] 0b 4e [2] 34 52 }

  condition:
    any of them
}