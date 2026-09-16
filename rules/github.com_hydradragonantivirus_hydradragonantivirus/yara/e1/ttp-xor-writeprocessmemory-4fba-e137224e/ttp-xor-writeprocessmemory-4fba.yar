rule TTP_XOR_WriteProcessMemory_4fba {
  strings:
    $key_4fba = { 18 c8 [2] 2a ea [2] 2c df [2] 02 df [2] 3d c3 }

  condition:
    any of them
}