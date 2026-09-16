rule TTP_XOR_WriteProcessMemory_0d36 {
  strings:
    $key_0d36 = { 5a 44 [2] 68 66 [2] 6e 53 [2] 40 53 [2] 7f 4f }

  condition:
    any of them
}