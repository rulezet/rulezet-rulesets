rule TTP_XOR_WriteProcessMemory_feae {
  strings:
    $key_feae = { a9 dc [2] 9b fe [2] 9d cb [2] b3 cb [2] 8c d7 }

  condition:
    any of them
}