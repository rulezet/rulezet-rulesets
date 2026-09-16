rule TTP_XOR_WriteProcessMemory_aa04 {
  strings:
    $key_aa04 = { fd 76 [2] cf 54 [2] c9 61 [2] e7 61 [2] d8 7d }

  condition:
    any of them
}