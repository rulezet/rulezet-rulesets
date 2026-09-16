rule TTP_XOR_WriteProcessMemory_2d6c {
  strings:
    $key_2d6c = { 7a 1e [2] 48 3c [2] 4e 09 [2] 60 09 [2] 5f 15 }

  condition:
    any of them
}