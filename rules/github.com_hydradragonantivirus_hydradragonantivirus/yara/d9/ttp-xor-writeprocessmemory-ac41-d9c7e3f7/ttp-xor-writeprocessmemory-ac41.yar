rule TTP_XOR_WriteProcessMemory_ac41 {
  strings:
    $key_ac41 = { fb 33 [2] c9 11 [2] cf 24 [2] e1 24 [2] de 38 }

  condition:
    any of them
}