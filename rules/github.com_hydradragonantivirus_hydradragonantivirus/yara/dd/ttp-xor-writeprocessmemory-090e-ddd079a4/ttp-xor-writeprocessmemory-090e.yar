rule TTP_XOR_WriteProcessMemory_090e {
  strings:
    $key_090e = { 5e 7c [2] 6c 5e [2] 6a 6b [2] 44 6b [2] 7b 77 }

  condition:
    any of them
}