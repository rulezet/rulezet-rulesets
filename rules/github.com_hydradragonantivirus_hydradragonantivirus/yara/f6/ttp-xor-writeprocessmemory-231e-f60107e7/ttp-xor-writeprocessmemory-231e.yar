rule TTP_XOR_WriteProcessMemory_231e {
  strings:
    $key_231e = { 74 6c [2] 46 4e [2] 40 7b [2] 6e 7b [2] 51 67 }

  condition:
    any of them
}