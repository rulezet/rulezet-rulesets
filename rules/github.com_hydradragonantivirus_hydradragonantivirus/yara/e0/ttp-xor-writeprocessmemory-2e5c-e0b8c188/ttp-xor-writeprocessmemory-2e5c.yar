rule TTP_XOR_WriteProcessMemory_2e5c {
  strings:
    $key_2e5c = { 79 2e [2] 4b 0c [2] 4d 39 [2] 63 39 [2] 5c 25 }

  condition:
    any of them
}