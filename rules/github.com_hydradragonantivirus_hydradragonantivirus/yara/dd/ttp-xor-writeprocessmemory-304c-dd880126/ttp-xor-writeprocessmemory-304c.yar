rule TTP_XOR_WriteProcessMemory_304c {
  strings:
    $key_304c = { 67 3e [2] 55 1c [2] 53 29 [2] 7d 29 [2] 42 35 }

  condition:
    any of them
}