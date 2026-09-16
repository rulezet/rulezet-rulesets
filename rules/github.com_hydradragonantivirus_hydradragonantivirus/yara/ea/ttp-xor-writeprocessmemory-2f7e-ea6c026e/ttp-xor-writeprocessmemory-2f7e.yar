rule TTP_XOR_WriteProcessMemory_2f7e {
  strings:
    $key_2f7e = { 78 0c [2] 4a 2e [2] 4c 1b [2] 62 1b [2] 5d 07 }

  condition:
    any of them
}