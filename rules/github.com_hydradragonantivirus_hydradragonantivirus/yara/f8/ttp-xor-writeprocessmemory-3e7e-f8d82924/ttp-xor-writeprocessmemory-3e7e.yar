rule TTP_XOR_WriteProcessMemory_3e7e {
  strings:
    $key_3e7e = { 69 0c [2] 5b 2e [2] 5d 1b [2] 73 1b [2] 4c 07 }

  condition:
    any of them
}