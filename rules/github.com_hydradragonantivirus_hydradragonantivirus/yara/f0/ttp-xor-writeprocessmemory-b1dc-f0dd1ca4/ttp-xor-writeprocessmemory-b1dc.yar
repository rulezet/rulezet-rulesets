rule TTP_XOR_WriteProcessMemory_b1dc {
  strings:
    $key_b1dc = { e6 ae [2] d4 8c [2] d2 b9 [2] fc b9 [2] c3 a5 }

  condition:
    any of them
}