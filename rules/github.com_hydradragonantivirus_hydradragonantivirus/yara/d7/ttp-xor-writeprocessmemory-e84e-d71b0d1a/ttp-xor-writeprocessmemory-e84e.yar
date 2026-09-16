rule TTP_XOR_WriteProcessMemory_e84e {
  strings:
    $key_e84e = { bf 3c [2] 8d 1e [2] 8b 2b [2] a5 2b [2] 9a 37 }

  condition:
    any of them
}