rule TTP_XOR_WriteProcessMemory_3bb3 {
  strings:
    $key_3bb3 = { 6c c1 [2] 5e e3 [2] 58 d6 [2] 76 d6 [2] 49 ca }

  condition:
    any of them
}