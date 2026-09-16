rule TTP_XOR_WriteProcessMemory_564c {
  strings:
    $key_564c = { 01 3e [2] 33 1c [2] 35 29 [2] 1b 29 [2] 24 35 }

  condition:
    any of them
}