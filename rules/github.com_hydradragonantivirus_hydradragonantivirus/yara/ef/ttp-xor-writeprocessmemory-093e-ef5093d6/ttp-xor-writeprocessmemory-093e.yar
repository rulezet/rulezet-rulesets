rule TTP_XOR_WriteProcessMemory_093e {
  strings:
    $key_093e = { 5e 4c [2] 6c 6e [2] 6a 5b [2] 44 5b [2] 7b 47 }

  condition:
    any of them
}