rule TTP_XOR_WriteProcessMemory_c90c {
  strings:
    $key_c90c = { 9e 7e [2] ac 5c [2] aa 69 [2] 84 69 [2] bb 75 }

  condition:
    any of them
}