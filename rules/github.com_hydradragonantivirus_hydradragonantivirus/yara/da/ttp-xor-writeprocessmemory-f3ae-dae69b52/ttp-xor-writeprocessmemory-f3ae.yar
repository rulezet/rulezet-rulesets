rule TTP_XOR_WriteProcessMemory_f3ae {
  strings:
    $key_f3ae = { a4 dc [2] 96 fe [2] 90 cb [2] be cb [2] 81 d7 }

  condition:
    any of them
}