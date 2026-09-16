rule TTP_XOR_WriteProcessMemory_822e {
  strings:
    $key_822e = { d5 5c [2] e7 7e [2] e1 4b [2] cf 4b [2] f0 57 }

  condition:
    any of them
}