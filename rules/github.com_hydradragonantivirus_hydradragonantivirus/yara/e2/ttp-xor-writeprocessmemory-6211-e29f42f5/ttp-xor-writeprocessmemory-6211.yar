rule TTP_XOR_WriteProcessMemory_6211 {
  strings:
    $key_6211 = { 35 63 [2] 07 41 [2] 01 74 [2] 2f 74 [2] 10 68 }

  condition:
    any of them
}