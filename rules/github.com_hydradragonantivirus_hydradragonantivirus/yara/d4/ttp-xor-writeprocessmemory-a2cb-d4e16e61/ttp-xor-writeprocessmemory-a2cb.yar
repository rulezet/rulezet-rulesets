rule TTP_XOR_WriteProcessMemory_a2cb {
  strings:
    $key_a2cb = { f5 b9 [2] c7 9b [2] c1 ae [2] ef ae [2] d0 b2 }

  condition:
    any of them
}