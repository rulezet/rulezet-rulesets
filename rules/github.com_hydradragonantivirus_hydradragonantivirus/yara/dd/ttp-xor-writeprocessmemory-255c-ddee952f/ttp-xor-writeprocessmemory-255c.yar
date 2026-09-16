rule TTP_XOR_WriteProcessMemory_255c {
  strings:
    $key_255c = { 72 2e [2] 40 0c [2] 46 39 [2] 68 39 [2] 57 25 }

  condition:
    any of them
}