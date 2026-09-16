rule TTP_XOR_WriteProcessMemory_131e {
  strings:
    $key_131e = { 44 6c [2] 76 4e [2] 70 7b [2] 5e 7b [2] 61 67 }

  condition:
    any of them
}