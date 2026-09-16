rule TTP_XOR_WriteProcessMemory_7c1c {
  strings:
    $key_7c1c = { 2b 6e [2] 19 4c [2] 1f 79 [2] 31 79 [2] 0e 65 }

  condition:
    any of them
}