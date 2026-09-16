rule TTP_XOR_WriteProcessMemory_3671 {
  strings:
    $key_3671 = { 61 03 [2] 53 21 [2] 55 14 [2] 7b 14 [2] 44 08 }

  condition:
    any of them
}