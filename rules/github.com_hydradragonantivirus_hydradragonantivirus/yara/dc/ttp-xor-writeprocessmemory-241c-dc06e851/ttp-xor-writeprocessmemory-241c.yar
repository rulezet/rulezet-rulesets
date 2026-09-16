rule TTP_XOR_WriteProcessMemory_241c {
  strings:
    $key_241c = { 73 6e [2] 41 4c [2] 47 79 [2] 69 79 [2] 56 65 }

  condition:
    any of them
}