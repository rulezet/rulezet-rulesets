rule TTP_XOR_WriteProcessMemory_bbae {
  strings:
    $key_bbae = { ec dc [2] de fe [2] d8 cb [2] f6 cb [2] c9 d7 }

  condition:
    any of them
}