rule TTP_XOR_WriteProcessMemory_39cc {
  strings:
    $key_39cc = { 6e be [2] 5c 9c [2] 5a a9 [2] 74 a9 [2] 4b b5 }

  condition:
    any of them
}