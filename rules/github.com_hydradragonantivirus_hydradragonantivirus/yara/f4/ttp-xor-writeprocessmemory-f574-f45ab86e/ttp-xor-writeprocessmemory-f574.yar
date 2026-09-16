rule TTP_XOR_WriteProcessMemory_f574 {
  strings:
    $key_f574 = { a2 06 [2] 90 24 [2] 96 11 [2] b8 11 [2] 87 0d }

  condition:
    any of them
}