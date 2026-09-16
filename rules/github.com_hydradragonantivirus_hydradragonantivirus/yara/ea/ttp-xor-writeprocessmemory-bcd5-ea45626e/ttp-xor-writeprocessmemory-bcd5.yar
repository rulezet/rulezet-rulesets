rule TTP_XOR_WriteProcessMemory_bcd5 {
  strings:
    $key_bcd5 = { eb a7 [2] d9 85 [2] df b0 [2] f1 b0 [2] ce ac }

  condition:
    any of them
}