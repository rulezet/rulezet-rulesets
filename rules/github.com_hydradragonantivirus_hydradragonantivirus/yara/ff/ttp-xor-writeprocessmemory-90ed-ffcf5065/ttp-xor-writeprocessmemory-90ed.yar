rule TTP_XOR_WriteProcessMemory_90ed {
  strings:
    $key_90ed = { c7 9f [2] f5 bd [2] f3 88 [2] dd 88 [2] e2 94 }

  condition:
    any of them
}