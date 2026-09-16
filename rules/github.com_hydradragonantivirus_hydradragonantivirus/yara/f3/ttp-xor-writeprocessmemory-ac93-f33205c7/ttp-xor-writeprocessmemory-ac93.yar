rule TTP_XOR_WriteProcessMemory_ac93 {
  strings:
    $key_ac93 = { fb e1 [2] c9 c3 [2] cf f6 [2] e1 f6 [2] de ea }

  condition:
    any of them
}