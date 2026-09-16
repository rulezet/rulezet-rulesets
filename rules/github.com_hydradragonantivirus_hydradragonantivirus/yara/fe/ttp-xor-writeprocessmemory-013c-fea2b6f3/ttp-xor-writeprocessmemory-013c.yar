rule TTP_XOR_WriteProcessMemory_013c {
  strings:
    $key_013c = { 56 4e [2] 64 6c [2] 62 59 [2] 4c 59 [2] 73 45 }

  condition:
    any of them
}