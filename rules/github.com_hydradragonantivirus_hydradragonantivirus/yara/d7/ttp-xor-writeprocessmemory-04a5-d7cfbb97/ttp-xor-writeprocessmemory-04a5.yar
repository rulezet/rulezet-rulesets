rule TTP_XOR_WriteProcessMemory_04a5 {
  strings:
    $key_04a5 = { 53 d7 [2] 61 f5 [2] 67 c0 [2] 49 c0 [2] 76 dc }

  condition:
    any of them
}