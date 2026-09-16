rule TTP_XOR_WriteProcessMemory_010c {
  strings:
    $key_010c = { 56 7e [2] 64 5c [2] 62 69 [2] 4c 69 [2] 73 75 }

  condition:
    any of them
}