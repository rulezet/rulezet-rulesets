rule TTP_XOR_WriteProcessMemory_0d7e {
  strings:
    $key_0d7e = { 5a 0c [2] 68 2e [2] 6e 1b [2] 40 1b [2] 7f 07 }

  condition:
    any of them
}