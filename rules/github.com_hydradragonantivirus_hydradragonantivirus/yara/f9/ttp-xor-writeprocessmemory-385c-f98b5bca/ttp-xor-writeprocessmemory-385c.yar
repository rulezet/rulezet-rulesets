rule TTP_XOR_WriteProcessMemory_385c {
  strings:
    $key_385c = { 6f 2e [2] 5d 0c [2] 5b 39 [2] 75 39 [2] 4a 25 }

  condition:
    any of them
}