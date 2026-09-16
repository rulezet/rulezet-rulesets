rule TTP_XOR_WriteProcessMemory_361e {
  strings:
    $key_361e = { 61 6c [2] 53 4e [2] 55 7b [2] 7b 7b [2] 44 67 }

  condition:
    any of them
}