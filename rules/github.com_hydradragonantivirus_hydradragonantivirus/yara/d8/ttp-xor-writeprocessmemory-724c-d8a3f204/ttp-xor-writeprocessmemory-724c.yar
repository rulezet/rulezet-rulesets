rule TTP_XOR_WriteProcessMemory_724c {
  strings:
    $key_724c = { 25 3e [2] 17 1c [2] 11 29 [2] 3f 29 [2] 00 35 }

  condition:
    any of them
}