rule TTP_XOR_WriteProcessMemory_f324 {
  strings:
    $key_f324 = { a4 56 [2] 96 74 [2] 90 41 [2] be 41 [2] 81 5d }

  condition:
    any of them
}