rule TTP_XOR_WriteProcessMemory_2e6c {
  strings:
    $key_2e6c = { 79 1e [2] 4b 3c [2] 4d 09 [2] 63 09 [2] 5c 15 }

  condition:
    any of them
}