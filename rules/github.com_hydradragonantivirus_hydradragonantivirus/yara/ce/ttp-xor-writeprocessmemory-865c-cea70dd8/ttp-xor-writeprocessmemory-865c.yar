rule TTP_XOR_WriteProcessMemory_865c {
  strings:
    $key_865c = { d1 2e [2] e3 0c [2] e5 39 [2] cb 39 [2] f4 25 }

  condition:
    any of them
}