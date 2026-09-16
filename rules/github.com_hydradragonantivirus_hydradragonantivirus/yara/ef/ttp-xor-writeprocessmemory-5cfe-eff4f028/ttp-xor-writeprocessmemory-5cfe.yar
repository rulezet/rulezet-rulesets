rule TTP_XOR_WriteProcessMemory_5cfe {
  strings:
    $key_5cfe = { 0b 8c [2] 39 ae [2] 3f 9b [2] 11 9b [2] 2e 87 }

  condition:
    any of them
}