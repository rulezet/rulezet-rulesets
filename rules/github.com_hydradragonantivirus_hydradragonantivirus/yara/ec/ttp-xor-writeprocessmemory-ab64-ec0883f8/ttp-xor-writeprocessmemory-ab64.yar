rule TTP_XOR_WriteProcessMemory_ab64 {
  strings:
    $key_ab64 = { fc 16 [2] ce 34 [2] c8 01 [2] e6 01 [2] d9 1d }

  condition:
    any of them
}