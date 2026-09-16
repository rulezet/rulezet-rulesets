rule TTP_XOR_WriteProcessMemory_72e3 {
  strings:
    $key_72e3 = { 25 91 [2] 17 b3 [2] 11 86 [2] 3f 86 [2] 00 9a }

  condition:
    any of them
}