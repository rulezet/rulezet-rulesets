rule TTP_XOR_WriteProcessMemory_694c {
  strings:
    $key_694c = { 3e 3e [2] 0c 1c [2] 0a 29 [2] 24 29 [2] 1b 35 }

  condition:
    any of them
}