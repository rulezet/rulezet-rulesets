rule TTP_XOR_WriteProcessMemory_0611 {
  strings:
    $key_0611 = { 51 63 [2] 63 41 [2] 65 74 [2] 4b 74 [2] 74 68 }

  condition:
    any of them
}