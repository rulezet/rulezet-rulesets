rule TTP_XOR_WriteProcessMemory_35e3 {
  strings:
    $key_35e3 = { 62 91 [2] 50 b3 [2] 56 86 [2] 78 86 [2] 47 9a }

  condition:
    any of them
}