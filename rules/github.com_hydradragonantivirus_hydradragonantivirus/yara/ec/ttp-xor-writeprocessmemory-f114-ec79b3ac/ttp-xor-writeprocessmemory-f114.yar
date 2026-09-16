rule TTP_XOR_WriteProcessMemory_f114 {
  strings:
    $key_f114 = { a6 66 [2] 94 44 [2] 92 71 [2] bc 71 [2] 83 6d }

  condition:
    any of them
}