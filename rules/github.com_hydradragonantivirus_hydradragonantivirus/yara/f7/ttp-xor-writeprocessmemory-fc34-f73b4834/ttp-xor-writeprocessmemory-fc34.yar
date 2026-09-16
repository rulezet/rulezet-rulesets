rule TTP_XOR_WriteProcessMemory_fc34 {
  strings:
    $key_fc34 = { ab 46 [2] 99 64 [2] 9f 51 [2] b1 51 [2] 8e 4d }

  condition:
    any of them
}