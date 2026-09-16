rule TTP_XOR_WriteProcessMemory_ffb3 {
  strings:
    $key_ffb3 = { a8 c1 [2] 9a e3 [2] 9c d6 [2] b2 d6 [2] 8d ca }

  condition:
    any of them
}