rule TTP_XOR_WriteProcessMemory_355c {
  strings:
    $key_355c = { 62 2e [2] 50 0c [2] 56 39 [2] 78 39 [2] 47 25 }

  condition:
    any of them
}