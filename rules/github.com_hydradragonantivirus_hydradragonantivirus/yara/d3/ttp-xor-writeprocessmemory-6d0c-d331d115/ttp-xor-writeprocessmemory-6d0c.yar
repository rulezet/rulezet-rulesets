rule TTP_XOR_WriteProcessMemory_6d0c {
  strings:
    $key_6d0c = { 3a 7e [2] 08 5c [2] 0e 69 [2] 20 69 [2] 1f 75 }

  condition:
    any of them
}