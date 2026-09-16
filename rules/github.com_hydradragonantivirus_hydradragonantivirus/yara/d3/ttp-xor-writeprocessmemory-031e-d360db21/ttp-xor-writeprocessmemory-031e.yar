rule TTP_XOR_WriteProcessMemory_031e {
  strings:
    $key_031e = { 54 6c [2] 66 4e [2] 60 7b [2] 4e 7b [2] 71 67 }

  condition:
    any of them
}