rule TTP_XOR_WriteProcessMemory_3e1c {
  strings:
    $key_3e1c = { 69 6e [2] 5b 4c [2] 5d 79 [2] 73 79 [2] 4c 65 }

  condition:
    any of them
}