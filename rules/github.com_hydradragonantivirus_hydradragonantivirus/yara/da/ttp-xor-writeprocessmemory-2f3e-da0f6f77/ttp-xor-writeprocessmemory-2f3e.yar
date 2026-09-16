rule TTP_XOR_WriteProcessMemory_2f3e {
  strings:
    $key_2f3e = { 78 4c [2] 4a 6e [2] 4c 5b [2] 62 5b [2] 5d 47 }

  condition:
    any of them
}