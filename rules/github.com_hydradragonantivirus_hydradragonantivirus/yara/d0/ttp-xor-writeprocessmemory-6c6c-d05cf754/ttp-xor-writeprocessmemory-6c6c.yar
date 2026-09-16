rule TTP_XOR_WriteProcessMemory_6c6c {
  strings:
    $key_6c6c = { 3b 1e [2] 09 3c [2] 0f 09 [2] 21 09 [2] 1e 15 }

  condition:
    any of them
}