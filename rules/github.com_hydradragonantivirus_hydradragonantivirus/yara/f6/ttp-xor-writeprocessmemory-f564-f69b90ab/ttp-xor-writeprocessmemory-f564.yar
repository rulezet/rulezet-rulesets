rule TTP_XOR_WriteProcessMemory_f564 {
  strings:
    $key_f564 = { a2 16 [2] 90 34 [2] 96 01 [2] b8 01 [2] 87 1d }

  condition:
    any of them
}