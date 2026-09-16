rule TTP_XOR_WriteProcessMemory_ac54 {
  strings:
    $key_ac54 = { fb 26 [2] c9 04 [2] cf 31 [2] e1 31 [2] de 2d }

  condition:
    any of them
}