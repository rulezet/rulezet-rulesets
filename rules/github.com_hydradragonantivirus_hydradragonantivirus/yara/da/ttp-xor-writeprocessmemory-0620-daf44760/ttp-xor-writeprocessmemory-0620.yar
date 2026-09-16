rule TTP_XOR_WriteProcessMemory_0620 {
  strings:
    $key_0620 = { 51 52 [2] 63 70 [2] 65 45 [2] 4b 45 [2] 74 59 }

  condition:
    any of them
}