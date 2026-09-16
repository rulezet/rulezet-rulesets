rule TTP_XOR_WriteProcessMemory_00e3 {
  strings:
    $key_00e3 = { 57 91 [2] 65 b3 [2] 63 86 [2] 4d 86 [2] 72 9a }

  condition:
    any of them
}