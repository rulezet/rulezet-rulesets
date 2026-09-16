rule TTP_XOR_WriteProcessMemory_53e3 {
  strings:
    $key_53e3 = { 04 91 [2] 36 b3 [2] 30 86 [2] 1e 86 [2] 21 9a }

  condition:
    any of them
}