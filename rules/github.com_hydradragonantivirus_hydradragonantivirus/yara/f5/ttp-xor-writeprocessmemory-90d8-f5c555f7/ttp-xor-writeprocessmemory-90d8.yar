rule TTP_XOR_WriteProcessMemory_90d8 {
  strings:
    $key_90d8 = { c7 aa [2] f5 88 [2] f3 bd [2] dd bd [2] e2 a1 }

  condition:
    any of them
}