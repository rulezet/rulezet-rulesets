rule TTP_XOR_WriteProcessMemory_0edc {
  strings:
    $key_0edc = { 59 ae [2] 6b 8c [2] 6d b9 [2] 43 b9 [2] 7c a5 }

  condition:
    any of them
}