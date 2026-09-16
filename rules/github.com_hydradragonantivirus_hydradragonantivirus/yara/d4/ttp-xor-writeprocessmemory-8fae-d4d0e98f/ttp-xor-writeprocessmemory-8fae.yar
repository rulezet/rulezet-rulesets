rule TTP_XOR_WriteProcessMemory_8fae {
  strings:
    $key_8fae = { d8 dc [2] ea fe [2] ec cb [2] c2 cb [2] fd d7 }

  condition:
    any of them
}