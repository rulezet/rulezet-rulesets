rule TTP_XOR_WriteProcessMemory_595c {
  strings:
    $key_595c = { 0e 2e [2] 3c 0c [2] 3a 39 [2] 14 39 [2] 2b 25 }

  condition:
    any of them
}