rule TTP_XOR_WriteProcessMemory_5a77 {
  strings:
    $key_5a77 = { 0d 05 [2] 3f 27 [2] 39 12 [2] 17 12 [2] 28 0e }

  condition:
    any of them
}