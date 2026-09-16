rule TTP_XOR_WriteProcessMemory_093c {
  strings:
    $key_093c = { 5e 4e [2] 6c 6c [2] 6a 59 [2] 44 59 [2] 7b 45 }

  condition:
    any of them
}