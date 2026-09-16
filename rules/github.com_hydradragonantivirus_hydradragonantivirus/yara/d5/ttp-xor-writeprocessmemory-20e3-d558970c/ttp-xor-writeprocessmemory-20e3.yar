rule TTP_XOR_WriteProcessMemory_20e3 {
  strings:
    $key_20e3 = { 77 91 [2] 45 b3 [2] 43 86 [2] 6d 86 [2] 52 9a }

  condition:
    any of them
}