rule TTP_XOR_WriteProcessMemory_e81e {
  strings:
    $key_e81e = { bf 6c [2] 8d 4e [2] 8b 7b [2] a5 7b [2] 9a 67 }

  condition:
    any of them
}