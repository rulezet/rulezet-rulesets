rule TTP_XOR_WriteProcessMemory_0fe3 {
  strings:
    $key_0fe3 = { 58 91 [2] 6a b3 [2] 6c 86 [2] 42 86 [2] 7d 9a }

  condition:
    any of them
}