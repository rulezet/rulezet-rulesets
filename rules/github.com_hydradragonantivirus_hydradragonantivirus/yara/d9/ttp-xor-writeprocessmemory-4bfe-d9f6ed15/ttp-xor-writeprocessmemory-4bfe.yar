rule TTP_XOR_WriteProcessMemory_4bfe {
  strings:
    $key_4bfe = { 1c 8c [2] 2e ae [2] 28 9b [2] 06 9b [2] 39 87 }

  condition:
    any of them
}