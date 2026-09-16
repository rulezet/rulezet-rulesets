rule TTP_XOR_WriteProcessMemory_3b5c {
  strings:
    $key_3b5c = { 6c 2e [2] 5e 0c [2] 58 39 [2] 76 39 [2] 49 25 }

  condition:
    any of them
}