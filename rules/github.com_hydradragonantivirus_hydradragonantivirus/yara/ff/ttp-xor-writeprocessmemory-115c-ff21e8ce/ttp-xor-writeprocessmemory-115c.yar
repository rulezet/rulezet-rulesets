rule TTP_XOR_WriteProcessMemory_115c {
  strings:
    $key_115c = { 46 2e [2] 74 0c [2] 72 39 [2] 5c 39 [2] 63 25 }

  condition:
    any of them
}