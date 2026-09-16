rule TTP_XOR_WriteProcessMemory_bcd3 {
  strings:
    $key_bcd3 = { eb a1 [2] d9 83 [2] df b6 [2] f1 b6 [2] ce aa }

  condition:
    any of them
}