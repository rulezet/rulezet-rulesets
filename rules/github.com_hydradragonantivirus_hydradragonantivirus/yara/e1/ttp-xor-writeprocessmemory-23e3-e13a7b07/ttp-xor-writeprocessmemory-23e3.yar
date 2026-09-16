rule TTP_XOR_WriteProcessMemory_23e3 {
  strings:
    $key_23e3 = { 74 91 [2] 46 b3 [2] 40 86 [2] 6e 86 [2] 51 9a }

  condition:
    any of them
}