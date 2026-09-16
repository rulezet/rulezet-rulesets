rule TTP_XOR_WriteProcessMemory_3e1e {
  strings:
    $key_3e1e = { 69 6c [2] 5b 4e [2] 5d 7b [2] 73 7b [2] 4c 67 }

  condition:
    any of them
}