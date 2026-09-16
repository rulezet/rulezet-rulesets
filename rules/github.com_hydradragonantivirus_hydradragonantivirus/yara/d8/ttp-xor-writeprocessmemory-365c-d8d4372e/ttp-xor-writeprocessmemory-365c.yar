rule TTP_XOR_WriteProcessMemory_365c {
  strings:
    $key_365c = { 61 2e [2] 53 0c [2] 55 39 [2] 7b 39 [2] 44 25 }

  condition:
    any of them
}