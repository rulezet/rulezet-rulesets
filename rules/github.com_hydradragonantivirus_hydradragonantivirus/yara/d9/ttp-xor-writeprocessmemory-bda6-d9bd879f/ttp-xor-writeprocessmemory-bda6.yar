rule TTP_XOR_WriteProcessMemory_bda6 {
  strings:
    $key_bda6 = { ea d4 [2] d8 f6 [2] de c3 [2] f0 c3 [2] cf df }

  condition:
    any of them
}