rule TTP_XOR_WriteProcessMemory_b1cb {
  strings:
    $key_b1cb = { e6 b9 [2] d4 9b [2] d2 ae [2] fc ae [2] c3 b2 }

  condition:
    any of them
}