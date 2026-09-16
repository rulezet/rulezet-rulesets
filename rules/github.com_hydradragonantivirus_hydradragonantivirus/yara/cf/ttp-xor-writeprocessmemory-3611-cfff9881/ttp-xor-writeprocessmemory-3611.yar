rule TTP_XOR_WriteProcessMemory_3611 {
  strings:
    $key_3611 = { 61 63 [2] 53 41 [2] 55 74 [2] 7b 74 [2] 44 68 }

  condition:
    any of them
}