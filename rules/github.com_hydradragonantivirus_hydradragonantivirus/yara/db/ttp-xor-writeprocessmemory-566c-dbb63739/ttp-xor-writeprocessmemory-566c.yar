rule TTP_XOR_WriteProcessMemory_566c {
  strings:
    $key_566c = { 01 1e [2] 33 3c [2] 35 09 [2] 1b 09 [2] 24 15 }

  condition:
    any of them
}