rule TTP_XOR_WriteProcessMemory_62ae {
  strings:
    $key_62ae = { 35 dc [2] 07 fe [2] 01 cb [2] 2f cb [2] 10 d7 }

  condition:
    any of them
}