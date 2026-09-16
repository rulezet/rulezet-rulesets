rule TTP_XOR_WriteProcessMemory_230c {
  strings:
    $key_230c = { 74 7e [2] 46 5c [2] 40 69 [2] 6e 69 [2] 51 75 }

  condition:
    any of them
}