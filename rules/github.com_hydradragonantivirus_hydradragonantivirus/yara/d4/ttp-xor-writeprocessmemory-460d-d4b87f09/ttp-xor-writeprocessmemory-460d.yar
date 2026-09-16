rule TTP_XOR_WriteProcessMemory_460d {
  strings:
    $key_460d = { 11 7f [2] 23 5d [2] 25 68 [2] 0b 68 [2] 34 74 }

  condition:
    any of them
}