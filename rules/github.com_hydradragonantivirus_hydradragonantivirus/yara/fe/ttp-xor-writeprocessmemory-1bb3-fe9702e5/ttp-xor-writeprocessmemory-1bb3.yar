rule TTP_XOR_WriteProcessMemory_1bb3 {
  strings:
    $key_1bb3 = { 4c c1 [2] 7e e3 [2] 78 d6 [2] 56 d6 [2] 69 ca }

  condition:
    any of them
}