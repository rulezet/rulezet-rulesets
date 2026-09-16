rule TTP_XOR_WriteProcessMemory_0de2 {
  strings:
    $key_0de2 = { 5a 90 [2] 68 b2 [2] 6e 87 [2] 40 87 [2] 7f 9b }

  condition:
    any of them
}