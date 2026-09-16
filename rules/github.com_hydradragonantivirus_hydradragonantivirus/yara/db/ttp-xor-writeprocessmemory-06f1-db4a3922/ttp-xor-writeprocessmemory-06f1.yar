rule TTP_XOR_WriteProcessMemory_06f1 {
  strings:
    $key_06f1 = { 51 83 [2] 63 a1 [2] 65 94 [2] 4b 94 [2] 74 88 }

  condition:
    any of them
}