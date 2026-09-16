rule TTP_XOR_WriteProcessMemory_09cb {
  strings:
    $key_09cb = { 5e b9 [2] 6c 9b [2] 6a ae [2] 44 ae [2] 7b b2 }

  condition:
    any of them
}