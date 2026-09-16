rule TTP_XOR_WriteProcessMemory_390c {
  strings:
    $key_390c = { 6e 7e [2] 5c 5c [2] 5a 69 [2] 74 69 [2] 4b 75 }

  condition:
    any of them
}