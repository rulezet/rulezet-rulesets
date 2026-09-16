rule TTP_XOR_WriteProcessMemory_8240 {
  strings:
    $key_8240 = { d5 32 [2] e7 10 [2] e1 25 [2] cf 25 [2] f0 39 }

  condition:
    any of them
}