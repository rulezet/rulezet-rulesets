rule TTP_XOR_WriteProcessMemory_d2ae {
  strings:
    $key_d2ae = { 85 dc [2] b7 fe [2] b1 cb [2] 9f cb [2] a0 d7 }

  condition:
    any of them
}