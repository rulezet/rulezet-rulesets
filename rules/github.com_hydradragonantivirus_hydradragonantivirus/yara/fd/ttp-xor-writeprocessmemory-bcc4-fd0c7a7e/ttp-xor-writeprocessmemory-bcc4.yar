rule TTP_XOR_WriteProcessMemory_bcc4 {
  strings:
    $key_bcc4 = { eb b6 [2] d9 94 [2] df a1 [2] f1 a1 [2] ce bd }

  condition:
    any of them
}