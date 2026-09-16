rule TTP_XOR_WriteProcessMemory_016c {
  strings:
    $key_016c = { 56 1e [2] 64 3c [2] 62 09 [2] 4c 09 [2] 73 15 }

  condition:
    any of them
}