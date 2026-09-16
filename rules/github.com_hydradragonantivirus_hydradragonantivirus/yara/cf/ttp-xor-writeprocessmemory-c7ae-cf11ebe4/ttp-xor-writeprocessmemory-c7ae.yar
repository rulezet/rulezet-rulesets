rule TTP_XOR_WriteProcessMemory_c7ae {
  strings:
    $key_c7ae = { 90 dc [2] a2 fe [2] a4 cb [2] 8a cb [2] b5 d7 }

  condition:
    any of them
}