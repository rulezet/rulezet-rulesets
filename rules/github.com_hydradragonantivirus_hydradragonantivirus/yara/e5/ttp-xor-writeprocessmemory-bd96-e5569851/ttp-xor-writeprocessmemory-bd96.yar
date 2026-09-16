rule TTP_XOR_WriteProcessMemory_bd96 {
  strings:
    $key_bd96 = { ea e4 [2] d8 c6 [2] de f3 [2] f0 f3 [2] cf ef }

  condition:
    any of them
}