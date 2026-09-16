rule TTP_XOR_WriteProcessMemory_0665 {
  strings:
    $key_0665 = { 51 17 [2] 63 35 [2] 65 00 [2] 4b 00 [2] 74 1c }

  condition:
    any of them
}