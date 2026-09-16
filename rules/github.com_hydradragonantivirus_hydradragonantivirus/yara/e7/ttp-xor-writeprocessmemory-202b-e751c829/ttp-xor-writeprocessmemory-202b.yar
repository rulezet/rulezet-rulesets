rule TTP_XOR_WriteProcessMemory_202b {
  strings:
    $key_202b = { 77 59 [2] 45 7b [2] 43 4e [2] 6d 4e [2] 52 52 }

  condition:
    any of them
}