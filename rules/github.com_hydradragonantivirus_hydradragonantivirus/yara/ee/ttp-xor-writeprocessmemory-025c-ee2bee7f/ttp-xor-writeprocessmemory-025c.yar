rule TTP_XOR_WriteProcessMemory_025c {
  strings:
    $key_025c = { 55 2e [2] 67 0c [2] 61 39 [2] 4f 39 [2] 70 25 }

  condition:
    any of them
}