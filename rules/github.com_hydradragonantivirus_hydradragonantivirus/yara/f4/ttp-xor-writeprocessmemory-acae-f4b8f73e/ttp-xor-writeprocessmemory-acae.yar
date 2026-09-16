rule TTP_XOR_WriteProcessMemory_acae {
  strings:
    $key_acae = { fb dc [2] c9 fe [2] cf cb [2] e1 cb [2] de d7 }

  condition:
    any of them
}