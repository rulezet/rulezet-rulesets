rule TTP_XOR_WriteProcessMemory_0a1e {
  strings:
    $key_0a1e = { 5d 6c [2] 6f 4e [2] 69 7b [2] 47 7b [2] 78 67 }

  condition:
    any of them
}