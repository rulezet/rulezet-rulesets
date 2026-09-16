rule TTP_XOR_WriteProcessMemory_bcc3 {
  strings:
    $key_bcc3 = { eb b1 [2] d9 93 [2] df a6 [2] f1 a6 [2] ce ba }

  condition:
    any of them
}