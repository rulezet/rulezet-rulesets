rule TTP_XOR_WriteProcessMemory_7c36 {
  strings:
    $key_7c36 = { 2b 44 [2] 19 66 [2] 1f 53 [2] 31 53 [2] 0e 4f }

  condition:
    any of them
}