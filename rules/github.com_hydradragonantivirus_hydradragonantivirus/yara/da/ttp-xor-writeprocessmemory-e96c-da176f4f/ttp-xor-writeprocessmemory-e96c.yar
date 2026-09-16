rule TTP_XOR_WriteProcessMemory_e96c {
  strings:
    $key_e96c = { be 1e [2] 8c 3c [2] 8a 09 [2] a4 09 [2] 9b 15 }

  condition:
    any of them
}