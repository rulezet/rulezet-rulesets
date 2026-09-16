rule TTP_XOR_WriteProcessMemory_0ec3 {
  strings:
    $key_0ec3 = { 59 b1 [2] 6b 93 [2] 6d a6 [2] 43 a6 [2] 7c ba }

  condition:
    any of them
}