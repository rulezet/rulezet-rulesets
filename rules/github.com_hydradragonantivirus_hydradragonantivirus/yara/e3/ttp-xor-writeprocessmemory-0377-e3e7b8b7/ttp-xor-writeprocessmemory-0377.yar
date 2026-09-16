rule TTP_XOR_WriteProcessMemory_0377 {
  strings:
    $key_0377 = { 54 05 [2] 66 27 [2] 60 12 [2] 4e 12 [2] 71 0e }

  condition:
    any of them
}