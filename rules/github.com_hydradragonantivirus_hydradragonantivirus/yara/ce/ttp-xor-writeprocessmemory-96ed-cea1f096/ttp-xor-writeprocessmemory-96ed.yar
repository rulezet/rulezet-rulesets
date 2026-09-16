rule TTP_XOR_WriteProcessMemory_96ed {
  strings:
    $key_96ed = { c1 9f [2] f3 bd [2] f5 88 [2] db 88 [2] e4 94 }

  condition:
    any of them
}