rule TTP_XOR_WriteProcessMemory_2d0c {
  strings:
    $key_2d0c = { 7a 7e [2] 48 5c [2] 4e 69 [2] 60 69 [2] 5f 75 }

  condition:
    any of them
}