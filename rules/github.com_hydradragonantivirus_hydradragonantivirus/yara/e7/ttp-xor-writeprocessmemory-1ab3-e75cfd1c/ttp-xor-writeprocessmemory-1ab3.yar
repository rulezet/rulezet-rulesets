rule TTP_XOR_WriteProcessMemory_1ab3 {
  strings:
    $key_1ab3 = { 4d c1 [2] 7f e3 [2] 79 d6 [2] 57 d6 [2] 68 ca }

  condition:
    any of them
}