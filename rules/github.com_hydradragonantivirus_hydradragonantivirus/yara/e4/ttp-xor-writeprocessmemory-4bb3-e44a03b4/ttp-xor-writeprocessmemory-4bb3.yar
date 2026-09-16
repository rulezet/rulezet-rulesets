rule TTP_XOR_WriteProcessMemory_4bb3 {
  strings:
    $key_4bb3 = { 1c c1 [2] 2e e3 [2] 28 d6 [2] 06 d6 [2] 39 ca }

  condition:
    any of them
}