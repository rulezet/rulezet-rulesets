rule TTP_XOR_WriteProcessMemory_e82e {
  strings:
    $key_e82e = { bf 5c [2] 8d 7e [2] 8b 4b [2] a5 4b [2] 9a 57 }

  condition:
    any of them
}