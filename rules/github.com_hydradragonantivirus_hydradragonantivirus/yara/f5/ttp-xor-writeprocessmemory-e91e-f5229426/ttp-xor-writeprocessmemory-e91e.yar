rule TTP_XOR_WriteProcessMemory_e91e {
  strings:
    $key_e91e = { be 6c [2] 8c 4e [2] 8a 7b [2] a4 7b [2] 9b 67 }

  condition:
    any of them
}