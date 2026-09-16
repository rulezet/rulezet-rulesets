rule TTP_XOR_WriteProcessMemory_7edc {
  strings:
    $key_7edc = { 29 ae [2] 1b 8c [2] 1d b9 [2] 33 b9 [2] 0c a5 }

  condition:
    any of them
}