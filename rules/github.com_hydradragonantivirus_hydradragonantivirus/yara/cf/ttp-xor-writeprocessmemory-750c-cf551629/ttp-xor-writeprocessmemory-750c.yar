rule TTP_XOR_WriteProcessMemory_750c {
  strings:
    $key_750c = { 22 7e [2] 10 5c [2] 16 69 [2] 38 69 [2] 07 75 }

  condition:
    any of them
}