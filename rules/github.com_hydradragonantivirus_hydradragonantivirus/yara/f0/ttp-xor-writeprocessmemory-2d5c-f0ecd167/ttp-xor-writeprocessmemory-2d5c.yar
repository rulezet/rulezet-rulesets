rule TTP_XOR_WriteProcessMemory_2d5c {
  strings:
    $key_2d5c = { 7a 2e [2] 48 0c [2] 4e 39 [2] 60 39 [2] 5f 25 }

  condition:
    any of them
}