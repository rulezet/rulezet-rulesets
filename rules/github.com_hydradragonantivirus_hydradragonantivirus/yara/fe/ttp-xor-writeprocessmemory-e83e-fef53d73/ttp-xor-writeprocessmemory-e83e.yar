rule TTP_XOR_WriteProcessMemory_e83e {
  strings:
    $key_e83e = { bf 4c [2] 8d 6e [2] 8b 5b [2] a5 5b [2] 9a 47 }

  condition:
    any of them
}