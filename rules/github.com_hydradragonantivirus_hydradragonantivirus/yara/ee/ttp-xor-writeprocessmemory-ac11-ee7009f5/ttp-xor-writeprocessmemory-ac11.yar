rule TTP_XOR_WriteProcessMemory_ac11 {
  strings:
    $key_ac11 = { fb 63 [2] c9 41 [2] cf 74 [2] e1 74 [2] de 68 }

  condition:
    any of them
}