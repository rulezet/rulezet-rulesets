rule TTP_XOR_WriteProcessMemory_6ffe {
  strings:
    $key_6ffe = { 38 8c [2] 0a ae [2] 0c 9b [2] 22 9b [2] 1d 87 }

  condition:
    any of them
}