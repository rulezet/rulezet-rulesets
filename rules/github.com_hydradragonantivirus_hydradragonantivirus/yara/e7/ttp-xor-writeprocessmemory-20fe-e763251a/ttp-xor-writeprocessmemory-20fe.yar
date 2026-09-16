rule TTP_XOR_WriteProcessMemory_20fe {
  strings:
    $key_20fe = { 77 8c [2] 45 ae [2] 43 9b [2] 6d 9b [2] 52 87 }

  condition:
    any of them
}