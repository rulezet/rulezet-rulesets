rule TTP_XOR_WriteProcessMemory_415c {
  strings:
    $key_415c = { 16 2e [2] 24 0c [2] 22 39 [2] 0c 39 [2] 33 25 }

  condition:
    any of them
}