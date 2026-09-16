rule TTP_XOR_WriteProcessMemory_0da3 {
  strings:
    $key_0da3 = { 5a d1 [2] 68 f3 [2] 6e c6 [2] 40 c6 [2] 7f da }

  condition:
    any of them
}