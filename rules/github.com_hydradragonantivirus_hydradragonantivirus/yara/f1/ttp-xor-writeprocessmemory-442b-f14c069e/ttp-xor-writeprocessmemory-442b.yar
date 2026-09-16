rule TTP_XOR_WriteProcessMemory_442b {
  strings:
    $key_442b = { 13 59 [2] 21 7b [2] 27 4e [2] 09 4e [2] 36 52 }

  condition:
    any of them
}