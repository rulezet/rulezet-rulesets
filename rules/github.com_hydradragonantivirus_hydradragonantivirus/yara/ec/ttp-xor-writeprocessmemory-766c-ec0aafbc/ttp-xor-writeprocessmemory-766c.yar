rule TTP_XOR_WriteProcessMemory_766c {
  strings:
    $key_766c = { 21 1e [2] 13 3c [2] 15 09 [2] 3b 09 [2] 04 15 }

  condition:
    any of them
}